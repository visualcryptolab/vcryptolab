import React, { useState, useCallback } from 'react';
import { Download, Upload, ZoomIn, ZoomOut, Info, ChevronDown, BookOpen } from 'lucide-react';
import {
    ORDERED_NODE_GROUPS,
    NODE_DEFINITIONS,
    HOVER_BORDER_TOOLBAR_CLASSES,
    TEXT_ICON_CLASSES
} from '../constants/appConstants';
import ToolbarButton from './ui/ToolbarButton';

const Toolbar = ({ addNode, onDownloadProject, onUploadProject, onZoomIn, onZoomOut }) => {
    const [collapsedGroups, setCollapsedGroups] = useState(() => ORDERED_NODE_GROUPS.reduce((acc, group) => { acc[group.name] = false; return acc; }, {}));
    const toggleGroup = useCallback((groupName) => setCollapsedGroups(prev => ({ ...prev, [groupName]: !prev[groupName] })), []);
    const handleInfoClick = (url) => window.open(url, '_blank');

    return (
        <div className="w-64 bg-gray-50 flex-shrink-0 border-r border-gray-200 shadow-lg flex flex-col h-full">
            <div className="p-4 pt-6 pb-4 border-b border-gray-200 flex flex-col justify-center items-center bg-white">
                <img
                    src="VCL - Horizonal logo + name.png"
                    alt="VisualCryptoLab"
                    className="w-full h-auto max-w-[180px]"
                    onError={(e) => { e.target.onerror = null; e.target.src = 'https://placehold.co/180x40/999/fff?text=VCL'; }}
                />
            </div>
            <div className="flex flex-col space-y-3 p-3 overflow-y-auto pt-4 flex-grow">
                {ORDERED_NODE_GROUPS.map((group) => (
                    <React.Fragment key={group.name}>
                        <div className="flex justify-between items-center text-xs font-bold uppercase text-gray-500 pt-2 pb-1 border-b border-gray-200 cursor-pointer hover:text-gray-700 transition" onClick={() => toggleGroup(group.name)}>
                            <span className="flex items-center space-x-1">
                                <span>{group.name}</span>
                                {group.name === 'SIMPLE RSA' && <button onClick={(e) => { e.stopPropagation(); handleInfoClick('https://github.com/visualcryptolab/vcryptolab/blob/main/docs/SimpleRSA.md'); }} className="p-0.5 rounded-full text-gray-400 hover:text-blue-500 transition duration-150 focus:outline-none" title="Docs"><Info className="w-3.5 h-3.5" /></button>}
                            </span>
                            <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${collapsedGroups[group.name] ? 'rotate-180' : ''}`} />
                        </div>
                        {!collapsedGroups[group.name] && (
                            <div className="space-y-1">
                                {group.types.map((type) => {
                                    const def = NODE_DEFINITIONS[type];
                                    if (!def) return null;
                                    const hoverBorderClass = HOVER_BORDER_TOOLBAR_CLASSES[def.color] || 'hover:border-gray-400';
                                    const iconTextColorClass = TEXT_ICON_CLASSES[def.color] || 'text-gray-600';
                                    return (
                                        <button key={type} onClick={() => addNode(type, def.label, def.color)} className={`w-full py-3 px-4 flex items-center justify-start space-x-3 bg-white hover:bg-gray-100 border-2 border-transparent ${hoverBorderClass} transition duration-150 text-gray-700 rounded-lg shadow-sm`}>
                                            {def.icon && <def.icon className={`w-5 h-5 ${iconTextColorClass} flex-shrink-0`} />}
                                            <span className="font-medium text-left">{def.label}</span>
                                        </button>
                                    );
                                })}
                            </div>
                        )}
                    </React.Fragment>
                ))}
            </div>
            <div className="flex justify-around space-x-1 p-3 pt-4 border-t border-gray-200 flex-shrink-0 bg-white shadow-inner">
                <ToolbarButton icon={Download} label="Export JSON" color="blue" onClick={onDownloadProject} />
                <ToolbarButton icon={Upload} label="Import JSON" color="orange" onChange={onUploadProject} isFileInput={true} />
                <ToolbarButton icon={BookOpen} label="Examples" color="indigo" onClick={() => window.open('https://github.com/visualcryptolab/vcryptolab/tree/main/docs/examples', '_blank')} />
                <ToolbarButton icon={ZoomOut} label="Zoom Out" color="teal" onClick={onZoomOut} />
                <ToolbarButton icon={ZoomIn} label="Zoom In" color="teal" onClick={onZoomIn} />
            </div>
        </div>
    );
};

export default Toolbar;
