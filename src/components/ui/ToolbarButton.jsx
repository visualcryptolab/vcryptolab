import React, { useRef } from 'react';
import { HOVER_BORDER_TOOLBAR_CLASSES, TEXT_ICON_CLASSES } from '../../constants/appConstants';

const ToolbarButton = ({ icon: Icon, label, color, onClick, onChange, isFileInput }) => {
    const hoverBorderClass = HOVER_BORDER_TOOLBAR_CLASSES[color] || 'hover:border-gray-400';
    const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';
    const inputRef = useRef(null);
    const handleClick = () => { if (isFileInput) inputRef.current.click(); else if (onClick) onClick(); };
    return (
        <div className="relative flex-shrink">
            <button onClick={handleClick} className={`w-full p-2 flex items-center justify-center bg-white hover:bg-gray-100 border-2 border-transparent ${hoverBorderClass} transition duration-150 text-gray-700 rounded-lg shadow-sm`} title={label}>
                {Icon && <Icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />}
            </button>
            {isFileInput && <input type="file" ref={inputRef} onChange={(e) => { if (e.target.files.length > 0) onChange(e.target); e.target.value = null; }} accept=".json" className="hidden" />}
        </div>
    );
};

export default ToolbarButton;
