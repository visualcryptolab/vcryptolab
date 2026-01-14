export const globalStyles = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

  html, body, #root {
    height: 100%;
    margin: 0;
    padding: 0;
    font-family: 'Inter', sans-serif;
  }

  @keyframes animate-pulse-slow {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
  }
  .animate-pulse-slow {
      animation: animate-pulse-slow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  }
  
  .connection-line-visible {
      stroke: #059669; /* Emerald 600 */
      fill: none;
      pointer-events: none;
  }
  .connection-hitbox {
      stroke: transparent;
      fill: none;
      cursor: pointer;
      pointer-events: stroke;
  }
  .connection-hitbox:hover {
      stroke: rgba(248, 113, 129, 0.5);
  }
  
  /* Custom scrollbar for panels */
  ::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }
  ::-webkit-scrollbar-track {
    background: #f1f1f1; 
  }
  ::-webkit-scrollbar-thumb {
    background: #c1c1c1; 
    border-radius: 3px;
  }
  ::-webkit-scrollbar-thumb:hover {
    background: #a8a8a8; 
  }
`;
