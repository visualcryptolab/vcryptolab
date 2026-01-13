import { PROJECT_SCHEMA_VERSION, NODE_DIMENSIONS } from '../constants/appConstants';

export const migrateProjectData = (projectData) => {
    const currentVersion = PROJECT_SCHEMA_VERSION;
    const importedVersion = projectData.schemaVersion || '1.0';
    if (importedVersion === currentVersion) return { migratedData: projectData, wasMigrated: false };
    let migratedData = { ...projectData };
    let wasMigrated = false;
    if (importedVersion < '1.1') {
        wasMigrated = true;
        migratedData.nodes = migratedData.nodes.map(node => {
            const newNode = { ...node };
            if (newNode.type === 'DATA_INPUT' && newNode.format && newNode.outputFormat === 'Text (UTF-8)') {
                if (['Binary', 'Hexadecimal', 'Decimal'].includes(newNode.format)) newNode.outputFormat = newNode.format;
            }
            if (!newNode.width || newNode.width < NODE_DIMENSIONS.minWidth) newNode.width = NODE_DIMENSIONS.initialWidth;
            if (!newNode.height || newNode.height < NODE_DIMENSIONS.minHeight) {
                if (newNode.type === 'XOR_OP' || newNode.type === 'SHIFT_OP' || newNode.type === 'DATA_SPLIT' || newNode.type === 'DATA_CONCAT') newNode.height = 300;
                else newNode.height = NODE_DIMENSIONS.initialHeight;
            }
            if (newNode.type === 'XOR_OP') { delete newNode.shiftType; delete newNode.shiftAmount; delete newNode.shiftDescription; }
            return newNode;
        });
    }
    migratedData.schemaVersion = currentVersion;
    return { migratedData, wasMigrated };
};

export const downloadFile = (content, filename, contentType) => {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};
