import React from 'react';
import { CheckCheck, Info, X } from 'lucide-react';

const StatusNotification = ({ status, message, onClose }) => {
    let bgColor;
    let IconComponent;
    switch (status) {
        case 'success': bgColor = 'bg-green-500'; IconComponent = CheckCheck; break;
        case 'warning': bgColor = 'bg-yellow-600'; IconComponent = Info; break;
        case 'error': default: bgColor = 'bg-red-500'; IconComponent = X; break;
    }
    return (
        <div className={`fixed bottom-4 right-4 p-4 rounded-lg shadow-xl text-white max-w-sm z-50 flex items-start space-x-3 transition-opacity duration-300 ${bgColor}`}>
            <IconComponent className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <div className="flex-grow"><p className="font-semibold text-sm">{status.toUpperCase()}</p><p className="text-sm">{message}</p></div>
            <button onClick={onClose} className="p-1 -mr-2 -mt-2 opacity-75 hover:opacity-100 transition"><X className="w-4 h-4" /></button>
        </div>
    );
};

export default StatusNotification;
