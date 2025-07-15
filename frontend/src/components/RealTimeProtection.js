import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
  Snackbar,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Tooltip,
  Chip,
  Paper as MuiPaper,
} from '@mui/material';
import { Delete as DeleteIcon, Info as InfoIcon, Notifications as NotificationsIcon, Restore as RestoreIcon } from '@mui/icons-material';
import axios from 'axios';

function RealTimeProtection() {
  const [protectionStatus, setProtectionStatus] = useState({
    real_time: true,
    web: true,
    email: true,
    file_system: true,
    network: true,
  });
  const [error, setError] = useState('');
  const [alerts, setAlerts] = useState([]);
  const [snackbar, setSnackbar] = useState({ open: false, message: '' });

  useEffect(() => {
    fetchProtectionStatus();
    fetchAlerts();
    // WebSocket for real-time alerts
    const ws = new WebSocket(`ws://${window.location.host}/ws/alerts`);
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'alert') {
        setAlerts(prev => [data.data, ...prev]);
        setSnackbar({ open: true, message: `${data.data.title}: ${data.data.message}` });
      }
    };
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
    return () => ws.close();
  }, []);

  const fetchProtectionStatus = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/protection');
      setProtectionStatus(response.data);
    } catch (error) {
      setError('Error fetching protection status');
    }
  };

  const fetchAlerts = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/alerts');
      setAlerts(response.data.alerts || []);
    } catch (error) {
      // Ignore fetch error for alerts
    }
  };

  const handleToggle = async (setting) => {
    try {
      const newStatus = !protectionStatus[setting];
      await axios.post('http://localhost:8000/api/protection', {
        setting: setting,
        enabled: newStatus
      });
      setProtectionStatus({
        ...protectionStatus,
        [setting]: newStatus,
      });
    } catch (error) {
      setError('Error updating protection status');
    }
  };

  const acknowledgeAlert = async (alertId) => {
    try {
      await axios.post(`http://localhost:8000/api/alerts/${alertId}/acknowledge`);
      setAlerts(alerts.map(alert =>
        alert.id === alertId ? { ...alert, acknowledged: true } : alert
      ));
    } catch (error) {
      // Ignore
    }
  };

  const deleteAlert = async (alertId) => {
    try {
      await axios.delete(`http://localhost:8000/api/alerts/${alertId}`);
      setAlerts(alerts.filter(alert => alert.id !== alertId));
    } catch (error) {
      // Ignore
    }
  };

  const restoreAlertFile = async (alert) => {
    try {
      if (!alert.file_info?.id) {
        setSnackbar({ open: true, message: 'No file to restore for this alert.' });
        return;
      }
      await axios.post('http://localhost:8000/api/restore', { quarantine_id: alert.file_info.id });
      setAlerts(alerts.filter(a => a.id !== alert.id));
      setSnackbar({ open: true, message: 'File restored successfully.' });
    } catch (error) {
      setSnackbar({ open: true, message: 'Error restoring file.' });
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const ProtectionSwitch = ({ label, setting }) => (
    <FormControlLabel
      control={
        <Switch
          checked={protectionStatus[setting]}
          onChange={() => handleToggle(setting)}
          color="primary"
        />
      }
      label={label}
    />
  );

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Real-Time Protection
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Paper elevation={3} sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Protection Settings
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <ProtectionSwitch
            label="Real-Time Protection"
            setting="real_time"
          />
          <Divider />
          <ProtectionSwitch
            label="Web Protection"
            setting="web"
          />
          <Divider />
          <ProtectionSwitch
            label="Email Protection"
            setting="email"
          />
          <Divider />
          <ProtectionSwitch
            label="File System Protection"
            setting="file_system"
          />
          <Divider />
          <ProtectionSwitch
            label="Network Protection"
            setting="network"
          />
        </Box>
      </Paper>

      {/* Real-Time Alerts Panel */}
      <MuiPaper elevation={3} sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          <NotificationsIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Real-Time Alerts
        </Typography>
        {alerts.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            No real-time alerts.
          </Typography>
        ) : (
          <List>
            {alerts.slice(0, 5).map((alert) => (
              <ListItem key={alert.id}>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip
                        label={alert.severity?.toUpperCase()}
                        color={getSeverityColor(alert.severity)}
                        size="small"
                      />
                      <Typography variant="body1">
                        {alert.title}
                      </Typography>
                    </Box>
                  }
                  secondary={
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        {alert.message}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {new Date(alert.timestamp).toLocaleString()}
                      </Typography>
                    </Box>
                  }
                />
                <ListItemSecondaryAction>
                  {!alert.acknowledged && (
                    <Tooltip title="Acknowledge">
                      <IconButton edge="end" onClick={() => acknowledgeAlert(alert.id)} size="small">
                        <InfoIcon />
                      </IconButton>
                    </Tooltip>
                  )}
                  <Tooltip title="Restore File">
                    <span>
                      <IconButton edge="end" onClick={() => restoreAlertFile(alert)} size="small" disabled={!alert.file_info?.id}>
                        <RestoreIcon />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title="Delete Alert">
                    <IconButton edge="end" onClick={() => deleteAlert(alert.id)} size="small">
                      <DeleteIcon />
                    </IconButton>
                  </Tooltip>
                </ListItemSecondaryAction>
              </ListItem>
            ))}
          </List>
        )}
      </MuiPaper>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        message={snackbar.message}
      />
    </Box>
  );
}

export default RealTimeProtection; 