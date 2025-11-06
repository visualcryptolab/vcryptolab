// src/components/CustomIcons.jsx
import React from 'react';

// --- Custom XOR Icon Component (The mathematical $\oplus$ symbol) ---
export const XORIcon = (props) => (
  <svg 
    xmlns="http://www.w3.org/2000/svg" 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2.5" 
    strokeLinecap="round" 
    strokeLinejoin="round" 
    className="w-6 h-6 absolute"
    {...props}
  >
    {/* Circle part */}
    <circle cx="12" cy="12" r="10" />
    {/* Plus (XOR) part */}
    <line x1="12" y1="8" x2="12" y2="16" />
    <line x1="8" y1="12" x2="16" y2="12" />
  </svg>
);

// --- Custom Bit Shift Icon Component (The $\rightleftharpoons$ symbol) ---
export const BitShiftIcon = (props) => (
  <svg 
    xmlns="http://www.w3.org/2000/svg" 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2.5" 
    strokeLinecap="round" 
    strokeLinejoin="round" 
    className="w-6 h-6 absolute"
    {...props}
  >
    {/* Right Arrow (Top) */}
    <polyline points="15 8 19 12 15 16" />
    <line x1="19" y1="12" x2="5" y2="12" />
    {/* Left Arrow (Bottom) - Flipped */}
    <polyline points="9 16 5 12 9 8" />
  </svg>
);