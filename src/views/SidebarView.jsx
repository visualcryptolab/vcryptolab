import Logo from "./../assets/logo.svg";
import React, { useState, useEffect } from "react";
import LinkIcon from "@mui/icons-material/Link";
import LockIcon from "@mui/icons-material/Lock";
import { useNavigate } from "react-router-dom";
import InputIcon from "@mui/icons-material/Input";
import OutputIcon from "@mui/icons-material/Output";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import PublicIcon from "@mui/icons-material/Public";
import styles from "../styles/SidebarView.module.css";
import SecurityIcon from "@mui/icons-material/Security";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import { Sidebar, Menu, MenuItem } from "react-pro-sidebar";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import SidebarController from "../controllers/SidebarController";
import DeleteRoundedIcon from "@mui/icons-material/DeleteRounded";
import { colors } from "@mui/material";

const SidebarView = ({ onNewNode, handleDelete }) => {
  const [collapsed, setCollapsed] = useState(SidebarController.getCollapsed());
  const [showText, setShowText] = useState(!collapsed);
  const navigate = useNavigate();

  useEffect(() => {
    if (collapsed) {
      const timer = setTimeout(() => {
        setShowText(false);
      }, 150);
      return () => clearTimeout(timer);
    } else {
      setShowText(true);
    }
  }, [collapsed]);

  const handleToggle = () => {
    setCollapsed(!collapsed);
  };

  const handleSelectItem = (item) => {
    onNewNode(item);
  };

  return (
    <div
      className={`${styles.sidebarContainer} ${
        collapsed ? styles.collapsed : styles.expanded
      }`}
    >
      <button className={styles.toggleButton} onClick={handleToggle}>
        {collapsed ? <ChevronRightIcon style={{color:"black"}} /> : <ChevronLeftIcon style={{color:"black"}} />}
      </button>
      <Sidebar
        className={styles.sidebar}
        collapsed={collapsed}
        width={"200px"}
        height="100vh"
      >
        <div className={styles.logoContainer} onClick={() => navigate("/")}>
          <img src={Logo} alt="Cryptolab" className={styles.logo} />
          {showText && (
            <span className={styles.logoText}>
              <span className={styles.crypto}>Crypto</span>
              <span className={styles.lab}>lab</span>
            </span>
          )}
        </div>
        <hr className={styles.separator} />
        <Menu height="100vh">
          <div className={styles.menuItems}>
            <MenuItem
              icon={<InputIcon />}
              onClick={() => handleSelectItem("Input")}
            >
              Input
            </MenuItem>
            <MenuItem
              icon={<OutputIcon />}
              onClick={() => handleSelectItem("Output")}
            >
              Output
            </MenuItem>
            <MenuItem
              icon={<LockIcon />}
              onClick={() => handleSelectItem("Encrypt")}
            >
              Encrypt
            </MenuItem>
            <MenuItem
              icon={<LockOpenIcon />}
              onClick={() => handleSelectItem("Decrypt")}
            >
              Decrypt
            </MenuItem>
            <MenuItem
              icon={<FingerprintIcon />}
              onClick={() => handleSelectItem("Hash")}
            >
              Hash
            </MenuItem>
            <MenuItem
              icon={<VpnKeyIcon />}
              onClick={() => handleSelectItem("Key Generator")}
              //onClick={() => handleSelectItem("Seed")}
            >
              Seed
            </MenuItem>
            <MenuItem
              icon={<PublicIcon />}
              onClick={() => handleSelectItem("Public Key")}
            >
              Public Key
            </MenuItem>
            <MenuItem
              icon={<SecurityIcon />}
              onClick={() => handleSelectItem("Private Key")}
            >
              Private Key
            </MenuItem>
            <MenuItem
              icon={<SwapHorizIcon />}
              onClick={() => handleSelectItem("Xor")}
            >
              Xor
            </MenuItem>
            <MenuItem
              icon={<LinkIcon />}
              onClick={() => handleSelectItem("Concatenate")}
            >
              Concatenate
            </MenuItem>
          </div>
          <div className={styles.deleteButtonContainer}>
            <MenuItem
              className={styles.deleteButton}
              icon={<DeleteRoundedIcon />}
              onClick={handleDelete}
            >
              Delete
            </MenuItem>
          </div>
        </Menu>
      </Sidebar>
    </div>
  );
};

export default SidebarView;
