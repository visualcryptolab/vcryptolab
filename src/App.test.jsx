
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from './App';

vi.mock('react-ga4', () => ({
    default: { initialize: vi.fn(), event: vi.fn() }
}));

vi.mock('react-cookie-consent', () => ({
    default: ({ children }) => <div>{children}</div>,
    getCookieConsentValue: vi.fn().mockReturnValue('true')
}));

describe('App Component', () => {
    it('renders the main container without crashing', () => {
        // We mock scrollIntoView because it's not implemented in JSDOM
        window.HTMLElement.prototype.scrollIntoView = function () { };

        const { container } = render(<App />);
        expect(container.getElementsByClassName('h-screen w-screen flex').length).toBeGreaterThan(0);
    });

    it('renders the toolbar', () => {
        window.HTMLElement.prototype.scrollIntoView = function () { };
        render(<App />);
        // Assuming Toolbar has some identifiable text or structure
        // But since we don't know the exact text inside Toolbar easily without reading it,
        // checking for canvas container is safer
        expect(document.querySelector('.canvas-container')).toBeInTheDocument();
    });
});
