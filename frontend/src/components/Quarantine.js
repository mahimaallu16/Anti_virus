import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Chip,
  Card,
  CardContent,
  Grid,
  Badge,
  Snackbar,
  Tooltip,
  Divider,
} from '@mui/material';
import {
  Restore as RestoreIcon,
  Delete as DeleteIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Info as InfoIcon,
  Notifications as NotificationsIcon,
} from '@mui/icons-material';
import api from '../api';

function Quarantine() {
  const [quarantinedFiles, setQuarantinedFiles] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogAction, setDialogAction] = useState('');
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({});

  useEffect(() => {
    fetchQuarantinedFiles();
    fetchAlerts();
    fetchStats();
    
    // Set up WebSocket connection for real-time alerts
    const ws = new WebSocket(`ws://${window.location.host}/ws/alerts`);
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'alert') {
        setAlerts(prev => [data.data, ...prev]);
        // Show notification for new alerts
        showNotification(data.data);
      }
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
    
    return () => {
      ws.close();
    };
  }, []);

  const fetchQuarantinedFiles = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/quarantine');
      setQuarantinedFiles(response.data.files || []);
    } catch (error) {
      setError('Error fetching quarantined files');
    } finally {
      setLoading(false);
    }
  };

  const fetchAlerts = async () => {
    try {
      const response = await api.get('/api/alerts');
      setAlerts(response.data.alerts || []);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await api.get('/api/quarantine/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const showNotification = (alert) => {
    // Create browser notification if supported
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(alert.title, {
        body: alert.message,
        icon: '/favicon.ico',
        tag: alert.id
      });
    }
  };

  const handleRestore = async (quarantineId) => {
    try {
      setLoading(true);
      await api.post('/api/restore', {
        quarantine_id: quarantineId,
      });
      setQuarantinedFiles(quarantinedFiles.filter(file => file.id !== quarantineId));
      setSuccess('File restored successfully');
      fetchStats();
    } catch (error) {
      setError(error.response?.data?.detail || 'Error restoring file');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (quarantineId) => {
    try {
      setLoading(true);
      await api.delete(`/api/quarantine/${quarantineId}`);
      setQuarantinedFiles(quarantinedFiles.filter(file => file.id !== quarantineId));
      setSuccess('File deleted from quarantine');
      fetchStats();
    } catch (error) {
      setError(error.response?.data?.detail || 'Error deleting file');
    } finally {
      setLoading(false);
    }
  };

  const acknowledgeAlert = async (alertId) => {
    try {
      await api.post(`/api/alerts/${alertId}/acknowledge`);
      setAlerts(alerts.map(alert => 
        alert.id === alertId ? { ...alert, acknowledged: true } : alert
      ));
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    }
  };

  const deleteAlert = async (alertId) => {
    try {
      await api.delete(`/api/alerts/${alertId}`);
      setAlerts(alerts.filter(alert => alert.id !== alertId));
    } catch (error) {
      console.error('Error deleting alert:', error);
    }
  };

  const openDialog = (file, action) => {
    setSelectedFile(file);
    setDialogAction(action);
    setDialogOpen(true);
  };

  const closeDialog = () => {
    setDialogOpen(false);
    setSelectedFile(null);
    setDialogAction('');
  };

  const confirmAction = () => {
    if (dialogAction === 'restore') {
      handleRestore(selectedFile.id);
    } else if (dialogAction === 'delete') {
      handleDelete(selectedFile.id);
    }
    closeDialog();
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

  const getRiskLevelColor = (riskLevel) => {
    switch (riskLevel) {
      case 'Critical': return 'error';
      case 'High': return 'warning';
      case 'Medium': return 'info';
      case 'Low': return 'success';
      case 'Minimal': return 'default';
      default: return 'default';
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Quarantine Management
      </Typography>

      {/* Statistics Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Quarantined
              </Typography>
              <Typography variant="h4">
                {stats.total_quarantined || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Size
              </Typography>
              <Typography variant="h4">
                {formatFileSize(stats.total_size || 0)}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Active Alerts
              </Typography>
              <Typography variant="h4">
                {stats.alerts?.unacknowledged || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Avg Threat Score
              </Typography>
              <Typography variant="h4">
                {Math.round(stats.average_threat_score || 0)}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Alerts Section */}
      {alerts.length > 0 && (
        <Paper elevation={3} sx={{ p: 2, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            <NotificationsIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Recent Alerts
          </Typography>
          <List>
            {alerts.slice(0, 5).map((alert) => (
              <ListItem key={alert.id}>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip 
                        label={alert.severity.toUpperCase()} 
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
                        {formatDate(alert.timestamp)}
                      </Typography>
                    </Box>
                  }
                />
                <ListItemSecondaryAction>
                  {!alert.acknowledged && (
                    <Tooltip title="Acknowledge">
                      <IconButton
                        edge="end"
                        onClick={() => acknowledgeAlert(alert.id)}
                        size="small"
                      >
                        <InfoIcon />
                      </IconButton>
                    </Tooltip>
                  )}
                  <Tooltip title="Delete Alert">
                    <IconButton
                      edge="end"
                      onClick={() => deleteAlert(alert.id)}
                      size="small"
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Tooltip>
                </ListItemSecondaryAction>
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>
          {success}
        </Alert>
      )}

      {/* Quarantined Files */}
      <Paper elevation={3} sx={{ p: 2 }}>
        <Typography variant="h6" gutterBottom>
          <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Quarantined Files ({quarantinedFiles.length})
        </Typography>

        {loading && (
          <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 2 }}>
            Loading...
          </Typography>
        )}

        {!loading && quarantinedFiles.length === 0 ? (
          <Typography variant="body1" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
            No files in quarantine
          </Typography>
        ) : (
          <List>
            {quarantinedFiles.map((file, index) => (
              <React.Fragment key={file.id}>
                <ListItem>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body1" fontWeight="medium">
                          {file.filename}
                        </Typography>
                        <Chip 
                          label={file.risk_level} 
                          color={getRiskLevelColor(file.risk_level)}
                          size="small"
                        />
                        {!file.exists && (
                          <Chip 
                            label="MISSING" 
                            color="error"
                            size="small"
                          />
                        )}
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography variant="body2" color="text.secondary">
                          {file.file_type} • {formatFileSize(file.file_size)} • Score: {file.threat_score}/100
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {file.quarantine_reason} • Quarantined: {formatDate(file.quarantine_date)}
                        </Typography>
                        {file.age_days > 0 && (
                          <Typography variant="caption" color="text.secondary">
                            Age: {file.age_days} days
                          </Typography>
                        )}
                      </Box>
                    }
                  />
                  <ListItemSecondaryAction>
                    <Tooltip title="Restore File">
                      <IconButton
                        edge="end"
                        aria-label="restore"
                        onClick={() => openDialog(file, 'restore')}
                        sx={{ mr: 1 }}
                        color="primary"
                      >
                        <RestoreIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete Permanently">
                      <IconButton
                        edge="end"
                        aria-label="delete"
                        onClick={() => openDialog(file, 'delete')}
                        color="error"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </ListItemSecondaryAction>
                </ListItem>
                {index < quarantinedFiles.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>
        )}
      </Paper>

      {/* Confirmation Dialog */}
      <Dialog open={dialogOpen} onClose={closeDialog} maxWidth="sm" fullWidth>
        <DialogTitle>
          {dialogAction === 'restore' ? '🔄 Restore File' : '🗑️ Delete File'}
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Are you sure you want to {dialogAction} "{selectedFile?.filename}"?
          </Typography>
          {selectedFile && (
            <Box sx={{ bgcolor: 'grey.50', p: 2, borderRadius: 1 }}>
              <Typography variant="body2" color="text.secondary">
                <strong>File Type:</strong> {selectedFile.file_type}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>Threat Score:</strong> {selectedFile.threat_score}/100
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>Risk Level:</strong> {selectedFile.risk_level}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>Size:</strong> {formatFileSize(selectedFile.file_size)}
              </Typography>
            </Box>
          )}
          {dialogAction === 'delete' && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              This action cannot be undone. The file will be permanently deleted.
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeDialog}>Cancel</Button>
          <Button
            onClick={confirmAction}
            color={dialogAction === 'restore' ? 'primary' : 'error'}
            variant="contained"
            disabled={loading}
          >
            {loading ? 'Processing...' : (dialogAction === 'restore' ? 'Restore' : 'Delete')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Success/Error Snackbar */}
      <Snackbar
        open={!!success}
        autoHideDuration={6000}
        onClose={() => setSuccess('')}
        message={success}
      />
    </Box>
  );
}

export default Quarantine; 