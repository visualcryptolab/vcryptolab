import React, { useEffect, useState, useCallback, useRef } from "react";
import { FaFileExport, FaFileImport, FaMoon, FaSun } from "react-icons/fa";
import * as htmlToImage from "html-to-image";
import debounce from "lodash.debounce";
import jsPDF from "jspdf";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  addEdge,
  Controls,
  MiniMap,
  MarkerType,
  useViewport,
  ReactFlowProvider,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import styles from "../styles/OpenDesignView.module.css";
import SidebarView from "./SidebarView";
import OpenDesignController from "../controllers/OpenDesignController";
import {
  ConcatenateNode,
  CustomResizerNode,
  DecryptNode,
  EncryptNode,
  HashNode,
  InputNode,
  OutputNode,
  KeyGeneratorNode,
  PrivateKeyNode,
  PublicKeyNode,
  ResizableNode,
  ResizableNodeSelected,
  SeedNode,
  XorNode,
} from "./components/nodes";
import { v4 as uuidv4 } from "uuid";
import { toast } from "react-toastify";
import { handleRemoveSelected } from "../utils/handleRemoveSelected";
import { IconButton, Menu, MenuItem } from "@mui/material";
import {
  FileDownload as FileDownloadIcon,
  FileUpload as FileUploadIcon,
} from "@mui/icons-material";
import zIndex from "@mui/material/styles/zIndex";

const OpenDesignView = () => {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedNodes, setSelectedNodes] = useState([]);
  const [selectedEdges, setSelectedEdges] = useState([]);
  const [copiedNodes, setCopiedNodes] = useState([]);
  const [copiedEdges, setCopiedEdges] = useState([]);
  const [snapGrid, setSnapGrid] = useState([1, 1]);
  const [undoStack, setUndoStack] = useState([]);
  const [redoStack, setRedoStack] = useState([]);
  const [nodeKeys, setNodeKeys] = useState({});
  const [isExporting, setIsExporting] = useState(false);

  const [authorName, setAuthorName] = useState("");
  const [isAuthorModalOpen, setIsAuthorModalOpen] = useState(false);
  const [isModalClosing, setIsModalClosing] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(false);

  const designRef = useRef(null);

  // Maintain sync between model and view
  useEffect(() => {
    setNodes(OpenDesignController.getNodes());
    setEdges(OpenDesignController.getEdges());
  }, []);

  let { viewport } = useViewport({
    x: 0,
    y: 0,
    zoom: 1,
  });

  const setViewport = (v) => {
    setSnapGrid([Math.max(1, 32 / v.zoom), Math.max(1, 32 / v.zoom)]);
    viewport = v;
  };

  const nodeTypes = {
    ResizableNode,
    ResizableNodeSelected,
    CustomResizerNode,
    InputNode,
    ConcatenateNode,
    DecryptNode,
    EncryptNode,
    HashNode,
    OutputNode,
    KeyGeneratorNode,
    PrivateKeyNode,
    PublicKeyNode,
    SeedNode,
    XorNode,
  };

  const updateViewportConst = ({ x, y, zoom }) => {
    setViewport({ x, y, zoom });
  };

  const handleSelectCopy = () => {
    const nodeIdMap = new Map();
    const newCopiedNodes = selectedNodes.map((node) => {
      const newId = uuidv4();
      nodeIdMap.set(node.id, newId);
      return {
        ...node,
        id: newId,
        position: { x: node.position.x + 50, y: node.position.y + 50 },
      };
    });

    setCopiedNodes(newCopiedNodes);

    const newCopiedEdges = selectedEdges.map((edge) => ({
      ...edge,
      id: uuidv4(),
      source: nodeIdMap.get(edge.source),
      target: nodeIdMap.get(edge.target),
    }));
    setCopiedEdges(newCopiedEdges);
  };

  const handlePaste = () => {
    const nodeIdMap = new Map();
    const newPastedNodes = copiedNodes.map((node) => {
      const newId = uuidv4();
      nodeIdMap.set(node.id, newId);
      return {
        ...node,
        id: newId,
        position: { x: node.position.x + 50, y: node.position.y + 50 },
      };
    });

    const newPastedEdges = copiedEdges.map((edge) => ({
      ...edge,
      id: uuidv4(),
      source: nodeIdMap.get(edge.source),
      target: nodeIdMap.get(edge.target),
    }));
    setNodes((nds) => [...nds, ...newPastedNodes]);
    setEdges((eds) => [...eds, ...newPastedEdges]);
  };

  const handleNewEdge = (params) => {
    const edgeExists = edges.some(
      (edge) => edge.source === params.source && edge.target === params.target
    );

    if (edgeExists) {
      toast.error("An edge already exists between these nodes.", {
        position: "top-right",
        autoClose: 2000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
      });
      return;
    }

    if (params.source === params.target) {
      toast.error("Cannot connect a node to itself.", {
        position: "top-right",
        autoClose: 2000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
      });
      return;
    }

    const newEdge = {
      id: `${params.source}-${params.sourceHandle}->${params.target}-${params.targetHandle}`,
      source: params.source,
      target: params.target,
      sourceHandle: params.sourceHandle,
      targetHandle: params.targetHandle,
      animated: true,
      markerEnd: {
        type: MarkerType.Arrow,
        width: 22,
        height: 22,
        color: "#FF0072",
      },
      style: {
        strokeWidth: 2,
        stroke: "#FF0072",
      },
      selectable: true,
    };
    OpenDesignController.addEdge(params.source, params.target);
    setEdges((eds) => addEdge(newEdge, eds));

    const sourceNode = nodes.find((node) => node.id === params.source);
    const targetNode = nodes.find((node) => node.id === params.target);

    if (sourceNode && targetNode) {

      
      /*const updatedTargetNode = {
        ...targetNode,
        data: {
          ...targetNode.data,
          input: sourceNode.data.output,
          rawInput: sourceNode.data.rawOutput,
          sourceId: sourceNode.id, // Add source node ID to the target node's data
          ...(sourceNode.data.seed && { seed: sourceNode.data.seed }),
          ...(sourceNode.data.pubKey && { pubKey: sourceNode.data.pubKey }),
          ...(sourceNode.data.privKey && { privKey: sourceNode.data.privKey }),
        },
      };*/
      const updatedTargetNode = {
        ...targetNode,
        data: {
          ...targetNode.data,
          sources: {
            ...targetNode.data?.sources, // Mantener datos previos si existen
            [sourceNode.id]: {
              ...targetNode.data?.sources?.[sourceNode.id], // Mantener los datos anteriores de este sourceNode si existen
              ...(sourceNode.data.output && { input: sourceNode.data.output }),
              ...(sourceNode.data.seed && { seed: sourceNode.data.seed }),
              ...(sourceNode.data.pubKey && { pubKey: sourceNode.data.pubKey }),
              ...(sourceNode.data.privKey && { privKey: sourceNode.data.privKey }),
            },
          },
        },
      };
      
      
      

      setNodes((nds) =>
        nds.map((n) => (n.id === targetNode.id ? updatedTargetNode : n))
      );
    }
  };

  const handleNewNode = (item) => {
    const type = item.replace(/\s+/g, "") + "Node";
    const newNode = {
      id: uuidv4(),
      type: type,
      position: { x: Math.random() * 400, y: Math.random() * 400 },
      data: { label: item },
    };
    OpenDesignController.addNode(newNode);
    setNodes((nds) => [...nds, newNode]);
    toast(`${type} added`, {
      position: "top-right",
      autoClose: 500,
      hideProgressBar: false,
      closeOnClick: true,
      pauseOnHover: true,
      draggable: true,
      progress: undefined,
    });
  };

  const handleNodesChange = (item) => {
    onNodesChange(item);
  };

  const cleanupNodeData = useCallback((nodeId) => {
    setNodes((nds) =>
      nds.map((node) => {
        if (node.id === nodeId) {
          return {
            ...node,
            data: {
              ...node.data,
              input: "",
              rawInput: "",
              output: "",
              rawOtput: "",
              pubKey: undefined,
              privKey: undefined,
              seed: undefined,
            },
          };
        }
        return node;
      })
    );
  }, []);

  const handleDelete = useCallback(() => {
    const deletedNodes = [...selectedNodes];
    const deletedEdges = [...selectedEdges];

    deletedEdges.forEach((edge) => {
      cleanupNodeData(edge.target);
      setNodeKeys((prev) => ({
        ...prev,
        [edge.target]: (prev[edge.target] || 0) + 1,
      }));
    });

    handleRemoveSelected(selectedNodes, selectedEdges, setNodes, setEdges);

    setUndoStack((prevUndoStack) => [
      ...prevUndoStack,
      { nodes: deletedNodes, edges: deletedEdges },
    ]);
    setRedoStack([]);
  }, [selectedNodes, selectedEdges, cleanupNodeData]);

  const handleUndo = () => {
    if (undoStack.length === 0) return;

    const lastDeleted = undoStack[undoStack.length - 1];
    setUndoStack((prevUndoStack) => prevUndoStack.slice(0, -1));
    setRedoStack((prevRedoStack) => [
      ...prevRedoStack,
      { nodes: lastDeleted.nodes, edges: lastDeleted.edges },
    ]);

    setNodes((nds) => [...nds, ...lastDeleted.nodes]);
    setEdges((eds) => [...eds, ...lastDeleted.edges]);
  };

  const handleRedo = () => {
    if (redoStack.length === 0) return;

    const lastUndone = redoStack[redoStack.length - 1];
    setRedoStack((prevRedoStack) => prevRedoStack.slice(0, -1));
    setUndoStack((prevUndoStack) => [
      ...prevUndoStack,
      { nodes: lastUndone.nodes, edges: lastUndone.edges },
    ]);

    handleRemoveSelected(
      lastUndone.nodes,
      lastUndone.edges,
      setNodes,
      setEdges
    );
  };

  const onSelectionChange = ({ nodes, edges }) => {
    setSelectedNodes(nodes || []);
    setSelectedEdges(edges || []);
  };

  useEffect(() => {
    const handleKeyDown = (event) => {
      const code = event.which || event.keyCode;
      let charCode = String.fromCharCode(code).toLowerCase();
      if ((event.ctrlKey || event.metaKey) && charCode === "c") {
        event.preventDefault();
        handleSelectCopy();
      } else if ((event.ctrlKey || event.metaKey) && charCode === "v") {
        handlePaste();
        event.preventDefault();
      } else if ((event.ctrlKey || event.metaKey) && charCode === "z") {
        event.preventDefault();
        handleUndo();
      } else if ((event.ctrlKey || event.metaKey) && charCode === "y") {
        event.preventDefault();
        handleRedo();
      }
    };
    window.addEventListener("keydown", handleKeyDown);

    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [
    selectedNodes,
    selectedNodes,
    copiedNodes,
    copiedEdges,
    undoStack,
    redoStack,
  ]);

  useEffect(() => {
    const updateNodes = debounce(() => {
      nodes.forEach((node) => {
        edges.forEach((edge) => {
          if (edge.source === node.id) {
            const targetNode = nodes.find((n) => n.id === edge.target);
            if (targetNode) {
              setNodes((nds) =>
                nds.map((n) => {
                  if (n.id === edge.target) {
                    return {
                      ...n,
                      data: {
                        ...n.data,
                        input: node.data.output,
                        seed: node.data.seed,
                        pubKey: node.data.pubKey,
                        privKey: node.data.privKey,
                      },
                      key: nodeKeys[n.id] || 0,
                    };
                  }
                  return n;
                })
              );
            }
          }
        });
      });
    }, 100);

    updateNodes();
    return () => updateNodes.cancel();
  }, [nodes, edges, nodeKeys]);

  useEffect(() => {
    setNodes((nds) =>
      nds.map((node) => ({
        ...node,
        style: {
          ...node.style,
          boxShadow: "none",
          borderRadius: "5px",
          transition: "box-shadow 0.125s ease, border-radius 0.125s ease",
        },
      }))
    );

    setNodes((nds) =>
      nds.map((node) =>
        selectedNodes.some((selectedNode) => selectedNode.id === node.id)
          ? {
              ...node,
              style: {
                ...node.style,
                boxShadow: "0 0 0 2px rgba(255, 0, 115, 0.5)",
                borderRadius: "9px",
                transition: "box-shadow 0.125s ease, border-radius 0.125s ease",
              },
            }
          : node
      )
    );
  }, [selectedNodes]);

  useEffect(() => {
    setEdges((eds) =>
      eds.map((edge) =>
        selectedEdges.some((selectedEdge) => selectedEdge.id === edge.id)
          ? {
              ...edge,
              style: {
                ...edge.style,
                stroke: "#8400ff",
                transition: "stroke 0.125s ease",
              },
              markerEnd: {
                type: MarkerType.Arrow,
                width: 22,
                height: 22,
                color: "#8400ff",
              },
            }
          : {
              ...edge,
              style: {
                ...edge.style,
                stroke: "#FF0072",
                transition: "stroke 0.125s ease",
              },
              markerEnd: {
                type: MarkerType.Arrow,
                width: 22,
                height: 22,
                color: "#FF0072",
              },
            }
      )
    );
  }, [selectedEdges]);

  const closeModal = (callback) => {
    setIsModalClosing(true);
    setTimeout(() => {
      setIsAuthorModalOpen(false);
      setIsModalClosing(false);
      if (callback) callback();
    }, 300); // 300ms matches the CSS animation duration
  };

  const handleExportToJsonClick = () => {
    closeModal(() => {
      setIsAuthorModalOpen(true);
    });
  };

  const handleAuthorNameSubmit = () => {
    closeModal(() => {
      exportToJson();
    });
  };

  const handleCancelModal = () => {
    closeModal();
  };

  const exportToPng = () => {
    if (designRef.current === null) {
      return;
    }
    setIsExporting(true);
    htmlToImage
      .toPng(designRef.current)
      .then((dataUrl) => {
        const link = document.createElement("a");
        link.download = "design.png";
        link.href = dataUrl;
        link.click();
      })
      .catch((error) => {
        console.error("Error exporting to PNG:", error);
      })
      .finally(() => {
        setIsExporting(false);
      });
  };

  const exportToSvg = () => {
    if (designRef.current === null) {
      return;
    }
    setIsExporting(true);
    htmlToImage
      .toSvg(designRef.current)
      .then((dataUrl) => {
        const link = document.createElement("a");
        link.download = "design.svg";
        link.href = dataUrl;
        link.click();
      })
      .catch((error) => {
        console.error("Error exporting to SVG:", error);
      })
      .finally(() => {
        setIsExporting(false);
      });
  };

  const exportToPdf = () => {
    if (designRef.current === null) {
      return;
    }
    setIsExporting(true);
    htmlToImage
      .toPng(designRef.current)
      .then((dataUrl) => {
        const pdf = new jsPDF({
          orientation: "landscape",
          unit: "px",
          format: [
            designRef.current.offsetWidth,
            designRef.current.offsetHeight,
          ],
        });
        pdf.addImage(
          dataUrl,
          "PNG",
          0,
          0,
          designRef.current.offsetWidth,
          designRef.current.offsetHeight
        );
        pdf.save("design.pdf");
      })
      .catch((error) => {
        console.error("Error exporting to PDF:", error);
      })
      .finally(() => {
        setIsExporting(false);
      });
  };

  const exportToJson = () => {
    const json = JSON.stringify({
      author: authorName || "Unknown Author",
      timestamp: new Date().toISOString(),
      nodes,
      edges,
    });
    const blob = new Blob([json], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "design.json";
    link.click();
  };

  const importFromJson = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const json = JSON.parse(e.target.result);
        setNodes(json.nodes);
        setEdges(json.edges);
      };
      reader.readAsText(file);
    }
  };

  const [anchorEl, setAnchorEl] = React.useState(null);
  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
  };

  return (
    <div
      className={`${styles.openDesignView} ${isDarkMode ? styles.dark : ""}`}
    >
      <ReactFlowProvider>
        <SidebarView onNewNode={handleNewNode} handleDelete={handleDelete} />
        <div className={styles.gridBg} ref={designRef}>
          <ReactFlow
            fitView
            snapToGrid
            nodes={nodes}
            edges={edges}
            snapGrid={snapGrid}
            nodeTypes={nodeTypes}
            onConnect={handleNewEdge}
            onDelete={handleDelete}
            onNodesChange={handleNodesChange}
            onEdgesChange={onEdgesChange}
            onSelectionChange={onSelectionChange}
            selectNodesOnDrag
            multiSelectionKeyCode={16}
            onViewportChange={(viewport) => setViewport(viewport)}
          >
            <Background
              color="#ccc"
              variant={
                isDarkMode ? BackgroundVariant.Dots : BackgroundVariant.Lines
              }
            />
            {!isExporting && (
              <>
                <MiniMap pannable zoomable position="bottom-right" />
                <MiniMap
                  nodeStrokeColor={(n) => {
                    if (n.type === "InputNode") return "#0041d0";
                    if (n.type === "OutputNode") return "#ff0072";
                    if (n.type === "EncryptNode") return "#ff0072";
                  }}
                  nodeColor={(n) => {
                    if (n.type === "selectorNode") return "#ff0072";
                    return "#fff";
                  }}
                />
                <Controls
                  className={styles.horizontalControls}
                  position="bottom-right"
                />
              </>
            )}
          </ReactFlow>
        </div>
        <div className={styles.exportButtons}>
          <IconButton
            onClick={toggleDarkMode}
            style={{
              width: "3.1rem",
              height: "3.1rem",
              borderRadius: "50%",
              backgroundColor: "var(--cryptolab-orange)",
              zIndex: "1000",
              transition: "all 0.125s ease",
              boxShadow:
                "0 4px 8px rgba(0, 0, 0, 0.13), 0 6px 20px rgba(0, 0, 0, 0.19)",
              marginRight: "0.5rem", // Add margin to separate from export button
            }}
          >
            {isDarkMode ? <FaSun /> : <FaMoon />}
          </IconButton>
          <IconButton
            aria-controls="export-menu"
            aria-haspopup="true"
            onClick={handleClick}
            style={{
              width: "3.1rem",
              height: "3.1rem",
              borderRadius: "50%",
              backgroundColor: "var(--cryptolab-orange)",
              zIndex: "1000",
              transition: "all 0.125s ease",
              boxShadow:
                "0 4px 8px rgba(0, 0, 0, 0.13), 0 6px 20px rgba(0, 0, 0, 0.19)",
            }}
          >
            <FileDownloadIcon />
          </IconButton>
          <Menu
            id="export-menu"
            anchorEl={anchorEl}
            keepMounted
            open={Boolean(anchorEl)}
            onClose={handleClose}
            className={styles.exportMenuClick}
          >
            <MenuItem style={{ fontWeight: 500 }} onClick={exportToPng}>
              Export to PNG
            </MenuItem>
            <MenuItem style={{ fontWeight: 500 }} onClick={exportToSvg}>
              Export to SVG
            </MenuItem>
            <MenuItem style={{ fontWeight: 500 }} onClick={exportToPdf}>
              Export to PDF
            </MenuItem>
            <MenuItem
              style={{ fontWeight: 500 }}
              onClick={handleExportToJsonClick}
            >
              Export to JSON
            </MenuItem>
            <MenuItem style={{ fontWeight: 500 }}>
              <label className={styles.importLabel}>
                <FileUploadIcon /> Import JSON
                <input
                  type="file"
                  accept=".json"
                  onChange={importFromJson}
                  style={{
                    display: "none",
                    backgroundColor: "var(--cryptolab-orange)",
                  }}
                />
              </label>
            </MenuItem>
          </Menu>
        </div>
      </ReactFlowProvider>
      {isAuthorModalOpen && (
        <div className={styles.modal} style={{ zIndex: 1001 }}>
          <div className={styles.modalContent}>
            <h2>Enter Author Name</h2>
            <input
              type="text"
              value={authorName}
              onChange={(e) => setAuthorName(e.target.value)}
              placeholder="Your Name"
              key={isAuthorModalOpen}
              className={styles.authorInput}
              style={{ zIndex: 1002 }}
            />
            <div className={styles.modalButtons}>
              <button onClick={handleAuthorNameSubmit}>Save</button>
              <button onClick={() => handleCancelModal(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OpenDesignView;
