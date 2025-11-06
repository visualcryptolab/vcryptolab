// src/components/Toolbar.jsx
import React, { useState, useCallback, useRef } from 'react';
import { Download, Upload, ZoomIn, ZoomOut, Info, ChevronDown } from 'lucide-react';
import { NODE_DEFINITIONS, ORDERED_NODE_GROUPS, HOVER_BORDER_TOOLBAR_CLASSES, TEXT_ICON_CLASSES } from '../constants/nodeDefinitions.js'; // Added .js extension
import { XORIcon, BitShiftIcon } from './CustomIcons';

// --- Helper Component for Toolbar Actions ---
const ToolbarButton = ({ icon: Icon, label, color, onClick, onChange, isFileInput }) => {
    const hoverBorderClass = HOVER_BORDER_TOOLBAR_CLASSES[color] || 'hover:border-gray-400';
    const iconTextColorClass = TEXT_ICON_CLASSES[color] || 'text-gray-600';
    const inputRef = useRef(null);

    const handleClick = () => {
        if (isFileInput) {
            inputRef.current.click();
        } else if (onClick) {
            onClick();
        }
    };

    return (
        <div className="relative flex-shrink">
            <button 
                onClick={handleClick}
                className={`w-full p-2 flex items-center justify-center bg-white hover:bg-gray-100 border-2 border-transparent ${hoverBorderClass} transition duration-150 text-gray-700 rounded-lg shadow-sm`}
                title={label}
            >
                {Icon && <Icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />}
            </button>
            
            {isFileInput && (
                <input 
                    type="file" 
                    ref={inputRef} 
                    onChange={(e) => {
                         onChange(e.target); // Pass the element itself which contains the 'files' property
                    }} 
                    accept=".json"
                    className="hidden"
                />
            )}
        </div>
    );
};


/**
 * Renders the main application toolbar with node creation and project actions.
 */
export const Toolbar = ({ addNode, onDownloadProject, onUploadProject, onZoomIn, onZoomOut }) => {
    const [collapsedGroups, setCollapsedGroups] = useState(() => {
        return ORDERED_NODE_GROUPS.reduce((acc, group) => {
            acc[group.name] = false;
            return acc;
        }, {});
    });

    const toggleGroup = useCallback((groupName) => {
        setCollapsedGroups(prev => ({
            ...prev,
            [groupName]: !prev[groupName]
        }));
    }, []);
    
    const handleInfoClick = (url) => {
        window.open(url, '_blank');
    };

    return (
        <div className="w-64 bg-gray-50 flex-shrink-0 border-r border-gray-200 shadow-lg flex flex-col">
            {/* Title/Logo Container */}
            <div className="p-4 pt-6 pb-4 border-b border-gray-200 flex flex-col justify-center items-center bg-white">
                <img 
                    src="VCL - Horizonal logo + name.png"
                    alt="VisualCryptoLab Logo and Name" 
                    className="w-full h-auto max-w-[180px]"
                    onError={(e) => {
                        e.target.onerror = null; 
                        e.target.src = 'https://placehold.co/180x40/999/fff?text=VCL'; 
                        e.target.alt = "VisualCryptoLab Logo Placeholder";
                    }}
                />
            </div>

            <div className="flex flex-col space-y-3 p-3 overflow-y-auto pt-4 flex-grow">
                
                {ORDERED_NODE_GROUPS.map((group, groupIndex) => (
                    <React.Fragment key={group.name}>
                        {/* Group Header (Clickable) */}
                        <div 
                            className="flex justify-between items-center text-xs font-bold uppercase text-gray-500 pt-2 pb-1 border-b border-gray-200 cursor-pointer hover:text-gray-700 transition"
                            onClick={() => toggleGroup(group.name)}
                        >
                            <span className="flex items-center space-x-1">
                                <span>{group.name}</span>
                                
                                {group.name === 'SIMPLE RSA' && (
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation(); 
                                            handleInfoClick('docs/SimpleRSA.md'); 
                                        }}
                                        className="p-0.5 rounded-full text-gray-400 hover:text-blue-500 transition duration-150 focus:outline-none"
                                        title="View Simple RSA Documentation"
                                    >
                                        <Info className="w-3.5 h-3.5" />
                                    </button>
                                )}
                                
                                {group.name === 'SYMMETRIC CRYPTO (AES)' && (
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation(); 
                                            handleInfoClick('https://www.youtube.com/watch?v=mlzxpkdXP58');
                                        }}
                                        className="p-0.5 rounded-full text-gray-400 hover:text-blue-500 transition duration-150 focus:outline-none"
                                        title="View AES Explanation Video"
                                    >
                                        <Info className="w-3.5 h-3.5" />
                                    </button>
                                )}
                            </span>
                            <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${collapsedGroups[group.name] ? 'rotate-180' : ''}`} />
                        </div>
                        
                        {/* Group Content (Conditionally Rendered/Collapsed) */}
                        {!collapsedGroups[group.name] && (
                            <div className="space-y-1">
                                {group.types.map((type) => {
                                    const def = NODE_DEFINITIONS[type];
                                    if (!def) return null; 
                                    
                                    const hoverBorderClass = HOVER_BORDER_TOOLBAR_CLASSES[def.color] || 'hover:border-gray-400';
                                    const iconTextColorClass = TEXT_ICON_CLASSES[def.color] || 'text-gray-600';

                                    return (
                                        <button 
                                            key={type}
                                            onClick={() => addNode(type, def.label, def.color)}
                                            className={`w-full py-3 px-4 flex items-center justify-start space-x-3 
                                                         bg-white hover:bg-gray-100 border-2 border-transparent ${hoverBorderClass}
                                                         transition duration-150 text-gray-700 rounded-lg shadow-sm`}
                                        >
                                            {def.icon && typeof def.icon === 'function' ? (
                                                <def.icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />
                                            ) : (
                                                def.icon && <def.icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />
                                            )}
                                            <span className="font-medium text-left">{def.label}</span>
                                        </button>
                                    );
                                })}
                            </div>
                        )}
                    </React.Fragment>
                ))}
                
            </div>
            
            {/* Action Buttons Section at the bottom */}
            <div className="flex justify-around space-x-1 p-3 pt-4 border-t border-gray-200 flex-shrink-0 bg-white shadow-inner">
                
                <ToolbarButton 
                    icon={Download} 
                    label="Download Project (JSON)" 
                    color="blue" 
                    onClick={onDownloadProject}
                />
                
                <ToolbarButton 
                    icon={Upload} 
                    label="Upload Project (JSON)" 
                    color="orange" 
                    onChange={onUploadProject}
                    isFileInput={true} 
                />
                
                <ToolbarButton 
                    icon={ZoomOut} 
                    label="Zoom Out" 
                    color="teal" 
                    onClick={onZoomOut}
                />

                <ToolbarButton 
                    icon={ZoomIn} 
                    label="Zoom In" 
                    color="teal" 
                    onClick={onZoomIn}
                />
            </div>
        </div>
    );
}