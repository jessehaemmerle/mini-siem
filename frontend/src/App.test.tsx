import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import App from './App';

vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ ok: false, status: 401, text: () => Promise.resolve('Unauthorized'), headers: new Headers() })));

describe('App', () => {
  it('renders login route', async () => {
    render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>,
    );
    expect(await screen.findByText('Mini SIEM')).toBeInTheDocument();
  });
});
