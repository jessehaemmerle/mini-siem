import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import accessible_tenant_ids, require_permission, resolve_tenant_id
from app.db.session import get_db
from app.models import Report, User
from app.schemas import ReportGenerateRequest, ReportRead
from app.services.audit_service import audit
from app.services.report_service import generate_report

router = APIRouter(prefix="/reports", tags=["reports"])


def _simple_pdf(title: str, body: str) -> bytes:
    text = (title + "\n\n" + body).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    lines = text.splitlines()[:45]
    content = "BT /F1 12 Tf 50 780 Td " + " T* ".join(f"({line[:95]})" for line in lines) + " ET"
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
        f"5 0 obj << /Length {len(content.encode())} >> stream\n{content}\nendstream endobj",
    ]
    pdf = "%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf.encode()))
        pdf += obj + "\n"
    xref_at = len(pdf.encode())
    pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    pdf += "".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:])
    pdf += f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n"
    return pdf.encode()


@router.get("", response_model=list[ReportRead])
def list_reports(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("reports:read"))):
    return db.scalars(select(Report).where(Report.tenant_id.in_(accessible_tenant_ids(db, user, tenant_id))).order_by(Report.created_at.desc())).all()


@router.post("/generate", response_model=ReportRead)
def generate(payload: ReportGenerateRequest, db: Session = Depends(get_db), user: User = Depends(require_permission("reports:write"))):
    tenant_id = resolve_tenant_id(db, user, tenant_id=payload.tenant_id)
    report = generate_report(db, tenant_id=tenant_id, report_type=payload.report_type, title=payload.title, created_by=user.id, start_time=payload.start_time, end_time=payload.end_time, file_type=payload.file_type)
    audit(db, action="report_generated", entity_type="report", entity_id=report.id, tenant_id=tenant_id, actor=user, new_value=payload.model_dump(mode="json"))
    db.commit()
    db.refresh(report)
    return report


@router.get("/{report_id}", response_model=ReportRead)
def get_report(report_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission("reports:read"))):
    report = db.get(Report, report_id)
    if not report or report.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{report_id}/download")
def download_report(report_id: str, format: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("reports:read"))):
    report = get_report(report_id, db, user)
    output_format = format or report.file_type
    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["section", "key", "value"])
        for section, values in report.content.items():
            if isinstance(values, dict):
                for key, value in values.items():
                    writer.writerow([section, key, value])
            else:
                writer.writerow([section, "", json.dumps(values)])
        return Response(buffer.getvalue(), media_type="text/csv")
    if output_format == "pdf":
        body = json.dumps(report.content, indent=2)
        return Response(_simple_pdf(report.title, body), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={report.id}.pdf"})
    return Response(json.dumps(report.content, indent=2), media_type="application/json")
