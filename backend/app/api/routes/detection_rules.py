from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import accessible_tenant_ids, require_permission, resolve_tenant_id
from app.db.session import get_db
from app.detection.engine import run_rule
from app.models import DetectionRule, User
from app.schemas import DetectionRuleCreate, DetectionRuleRead, DetectionRuleUpdate
from app.services.audit_service import audit

router = APIRouter(prefix="/detection-rules", tags=["detection-rules"])


@router.get("", response_model=list[DetectionRuleRead])
def list_rules(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_permission("rules:read"))):
    return db.scalars(select(DetectionRule).where(DetectionRule.tenant_id.in_(accessible_tenant_ids(db, user, tenant_id))).order_by(DetectionRule.name)).all()


@router.post("", response_model=DetectionRuleRead, status_code=status.HTTP_201_CREATED)
def create_rule(payload: DetectionRuleCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("rules:write"))):
    tenant_id = resolve_tenant_id(db, user, tenant_id=payload.tenant_id)
    rule = DetectionRule(tenant_id=tenant_id, created_by=user.id, updated_by=user.id, **payload.model_dump(exclude={"tenant_id"}))
    db.add(rule)
    audit(db, action="detection_rule_created", entity_type="detection_rule", entity_id=rule.id, tenant_id=tenant_id, actor=user, new_value=payload.model_dump(), request=request)
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/{rule_id}", response_model=DetectionRuleRead)
def get_rule(rule_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission("rules:read"))):
    rule = db.get(DetectionRule, rule_id)
    if not rule or rule.tenant_id not in accessible_tenant_ids(db, user):
        raise HTTPException(status_code=404, detail="Detection rule not found")
    return rule


@router.put("/{rule_id}", response_model=DetectionRuleRead)
def update_rule(rule_id: str, payload: DetectionRuleUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("rules:write"))):
    rule = get_rule(rule_id, db, user)
    old = {key: getattr(rule, key) for key in payload.model_fields}
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(rule, key, value)
    rule.updated_by = user.id
    audit(db, action="detection_rule_updated", entity_type="detection_rule", entity_id=rule.id, tenant_id=rule.tenant_id, actor=user, old_value=old, new_value=payload.model_dump(exclude_unset=True), request=request)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}")
def delete_rule(rule_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("rules:write"))):
    rule = get_rule(rule_id, db, user)
    db.delete(rule)
    audit(db, action="detection_rule_deleted", entity_type="detection_rule", entity_id=rule_id, tenant_id=rule.tenant_id, actor=user, request=request)
    db.commit()
    return {"ok": True}


@router.post("/{rule_id}/test")
def test_rule(rule_id: str, db: Session = Depends(get_db), user: User = Depends(require_permission("rules:write"))):
    rule = get_rule(rule_id, db, user)
    created = run_rule(db, rule)
    return {"alerts_created": created}


@router.post("/{rule_id}/enable", response_model=DetectionRuleRead)
def enable_rule(rule_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("rules:write"))):
    return update_rule(rule_id, DetectionRuleUpdate(enabled=True), request, db, user)


@router.post("/{rule_id}/disable", response_model=DetectionRuleRead)
def disable_rule(rule_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_permission("rules:write"))):
    return update_rule(rule_id, DetectionRuleUpdate(enabled=False), request, db, user)
