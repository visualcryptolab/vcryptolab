import React from 'react';

export function BitShiftIcon(props) {
    return (
        <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="w-6 h-6"
            {...props}
        >
            <polyline points="15 8 19 12 15 16" />
            <line x1="19" y1="12" x2="5" y2="12" />
            <polyline points="9 16 5 12 9 8" />
        </svg>
    );
}
