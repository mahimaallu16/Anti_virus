import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Grid,
  Paper,
  Typography,
  TextField,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Alert,
  Input,
  Chip,
  Tooltip,
} from '@mui/material';
import {
  Delete as DeleteIcon,
  PlayArrow as PlayArrowIcon,
  Stop as StopIcon,
  CloudUpload as CloudUploadIcon,
} from '@mui/icons-material';
import api from '../api';

function ScanCenter() {
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [customPath, setCustomPath] = useState('');
  const [scanResults, setScanResults] = useState([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [uploading, setUploading] = useState(false);

  const startScan = async (scanType, path = '') => {
    try {
      setScanning(true);
      setProgress(0);
      setScanResults([]);
      setError('');
      setSuccess('');

      // Simulate progress for different scan types
      const progressInterval = setInterval(() => {
        setProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);

      const response = await api.post('/api/scan', {
        type: scanType,
        path: path,
      });

      clearInterval(progressInterval);
      setProgress(100);
      setScanResults(response.data.threats);
      
      // Show success message for clean scans
      if (response.data.threats_found === 0) {
        setError(''); // Clear any previous errors
        setSuccess('Scan completed successfully without threats');
      }
    } catch (error) {
      setError(error.response?.data?.detail || error.response?.data?.message || 'An error occurred during scanning');
    } finally {
      setScanning(false);
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    setUploading(true);
    setError('');
    setScanResults([]);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const uploadResponse = await api.post('/api/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      const filePath = uploadResponse.data.path;
      await startScan('upload', filePath);
    } catch (error) {
      setError(error.response?.data?.detail || error.response?.data?.message || 'File upload or scan failed');
    } finally {
      setUploading(false);
    }
  };

  const quarantineFile = async (filePath) => {
    try {
      // Find the threat information for this file
      const threat = scanResults.find(result => result.path === filePath);
      
      if (!threat) {
        setError('Threat information not found for this file');
        return;
      }

      // Show confirmation dialog for high-risk files
      const threatScore = threat.score || 0;
      const isHighRisk = threatScore >= 80;
      
      if (isHighRisk) {
        const confirmed = window.confirm(
          `🚨 HIGH RISK THREAT DETECTED!\n\n` +
          `File: ${filePath}\n` +
          `Threat Score: ${threatScore}/100\n` +
          `Threat Type: ${threat.threat}\n\n` +
          `This file will be automatically quarantined for your safety.\n` +
          `Do you want to proceed?`
        );
        
        if (!confirmed) {
          return;
        }
      }
      
      const response = await api.post('/api/quarantine', {
        file_path: filePath,
        threat_score: threatScore,
        threat_type: threat.threat || "Unknown",
        quarantine_reason: threat.threat || "Suspicious file",
        threat_details: threat.details || {}
      });
      
      // Remove from scan results
      setScanResults(scanResults.filter(result => result.path !== filePath));
      
      // Show success message
      const riskLevel = threatScore >= 90 ? 'CRITICAL' : 
                       threatScore >= 80 ? 'HIGH' : 
                       threatScore >= 60 ? 'MEDIUM' : 'LOW';
      
      setSuccess(`✅ File quarantined successfully!\nRisk Level: ${riskLevel}\nThreat Score: ${threatScore}/100`);
      
      // Show browser notification if supported
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('🚨 Threat Quarantined', {
          body: `File "${filePath.split('/').pop()}" has been quarantined. Risk: ${riskLevel}`,
          icon: '/favicon.ico'
        });
      }
      
    } catch (error) {
      setError(error.response?.data?.detail || error.response?.data?.message || 'Error quarantining file');
    }
  };

  const autoQuarantineHighRiskFiles = async () => {
    const highRiskFiles = scanResults.filter(result => (result.score || 0) >= 80);
    
    if (highRiskFiles.length === 0) {
      return;
    }
    
    const confirmed = window.confirm(
      `🚨 HIGH RISK THREATS DETECTED!\n\n` +
      `${highRiskFiles.length} file(s) with high threat scores (≥80) have been detected.\n\n` +
      `These files will be automatically quarantined for your safety.\n` +
      `Do you want to quarantine all high-risk files?`
    );
    
    if (!confirmed) {
      return;
    }
    
    let quarantinedCount = 0;
    
    for (const threat of highRiskFiles) {
      try {
        await api.post('/api/quarantine', {
          file_path: threat.path,
          threat_score: threat.score || 0,
          threat_type: threat.threat || "Unknown",
          quarantine_reason: threat.threat || "High-risk threat",
          threat_details: threat.details || {}
        });
        quarantinedCount++;
      } catch (error) {
        console.error(`Error quarantining ${threat.path}:`, error);
      }
    }
    
    // Remove quarantined files from results
    setScanResults(scanResults.filter(result => (result.score || 0) < 80));
    
    if (quarantinedCount > 0) {
      setSuccess(`✅ ${quarantinedCount} high-risk file(s) quarantined automatically!`);
      
      // Show browser notification
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('🚨 Threats Quarantined', {
          body: `${quarantinedCount} high-risk files have been quarantined automatically.`,
          icon: '/favicon.ico'
        });
      }
    }
  };

  // Auto-quarantine high-risk files when scan completes
  useEffect(() => {
    if (scanResults.length > 0 && !scanning) {
      const highRiskCount = scanResults.filter(result => (result.score || 0) >= 80).length;
      if (highRiskCount > 0) {
        // Auto-quarantine after a short delay
        setTimeout(() => {
          autoQuarantineHighRiskFiles();
        }, 2000);
      }
    }
  }, [scanResults, scanning]);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Scan Center
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper elevation={3} sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Scan Options
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6} md={3}>
                <Button
                  fullWidth
                  variant="contained"
                  startIcon={<PlayArrowIcon />}
                  onClick={() => startScan('quick')}
                  disabled={scanning}
                >
                  Quick Scan
                </Button>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Button
                  fullWidth
                  variant="contained"
                  startIcon={<PlayArrowIcon />}
                  onClick={() => startScan('full')}
                  disabled={scanning}
                >
                  Full Scan
                </Button>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Button
                  fullWidth
                  variant="contained"
                  startIcon={<PlayArrowIcon />}
                  onClick={() => startScan('system')}
                  disabled={scanning}
                >
                  System Scan
                </Button>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <TextField
                    fullWidth
                    size="small"
                    placeholder="Custom path"
                    value={customPath}
                    onChange={(e) => setCustomPath(e.target.value)}
                    disabled={scanning}
                  />
                  <Button
                    variant="contained"
                    startIcon={<PlayArrowIcon />}
                    onClick={() => startScan('custom', customPath)}
                    disabled={scanning || !customPath}
                  >
                    Scan
                  </Button>
                </Box>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Button
                  fullWidth
                  variant="contained"
                  component="label"
                  startIcon={<CloudUploadIcon />}
                  disabled={uploading || scanning}
                >
                  {uploading ? 'Uploading...' : 'Upload & Scan'}
                  <Input
                    type="file"
                    sx={{ display: 'none' }}
                    onChange={handleFileUpload}
                    inputProps={{ accept: '*' }}
                  />
                </Button>
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        {scanning && (
          <Grid item xs={12}>
            <Paper elevation={3} sx={{ p: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Typography variant="body1" sx={{ mr: 2 }}>
                  Scanning...
                </Typography>
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<StopIcon />}
                  onClick={() => setScanning(false)}
                >
                  Stop
                </Button>
              </Box>
              <LinearProgress variant="determinate" value={progress} />
            </Paper>
          </Grid>
        )}

        {scanResults.length > 0 && (
          <Grid item xs={12}>
            <Paper elevation={3} sx={{ p: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6">
                  🚨 Scan Results ({scanResults.length} threats detected)
                </Typography>
                {scanResults.filter(result => (result.score || 0) >= 80).length > 0 && (
                  <Button
                    variant="contained"
                    color="error"
                    startIcon={<DeleteIcon />}
                    onClick={autoQuarantineHighRiskFiles}
                  >
                    Quarantine High-Risk Files
                  </Button>
                )}
              </Box>
              
              <List>
                {scanResults.map((result, index) => {
                  const threatScore = result.score || 0;
                  const riskLevel = threatScore >= 90 ? 'CRITICAL' : 
                                   threatScore >= 80 ? 'HIGH' : 
                                   threatScore >= 60 ? 'MEDIUM' : 'LOW';
                  
                  const getRiskColor = (level) => {
                    switch (level) {
                      case 'CRITICAL': return 'error';
                      case 'HIGH': return 'warning';
                      case 'MEDIUM': return 'info';
                      case 'LOW': return 'success';
                      default: return 'default';
                    }
                  };
                  
                  return (
                    <ListItem key={index} alignItems="flex-start" sx={{ 
                      border: 1, 
                      borderColor: getRiskColor(riskLevel) === 'error' ? 'error.main' : 
                                  getRiskColor(riskLevel) === 'warning' ? 'warning.main' : 'grey.300',
                      borderRadius: 1,
                      mb: 1,
                      bgcolor: getRiskColor(riskLevel) === 'error' ? 'error.light' : 
                              getRiskColor(riskLevel) === 'warning' ? 'warning.light' : 'grey.50'
                    }}>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography variant="body1" fontWeight="medium">
                              {result.path.split('/').pop() || result.path}
                            </Typography>
                            <Chip 
                              label={riskLevel} 
                              color={getRiskColor(riskLevel)}
                              size="small"
                            />
                            <Chip 
                              label={`Score: ${threatScore}/100`} 
                              variant="outlined"
                              size="small"
                            />
                          </Box>
                        }
                        secondary={
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              <strong>Threat:</strong> {result.threat}
                            </Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                              <strong>Full Path:</strong> {result.path}
                            </Typography>
                            
                            {result.details && (
                              <Box sx={{ mt: 1, p: 1, bgcolor: 'white', borderRadius: 1, border: 1, borderColor: 'grey.300' }}>
                                <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                                  <strong>Detection Details:</strong>
                                </Typography>
                                
                                {result.details.rule && (
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Rule:</strong> {result.details.namespace ? `${result.details.namespace} :: ` : ''}{result.details.rule}
                                  </Typography>
                                )}
                                
                                {result.details.meta?.description && (
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Description:</strong> {result.details.meta.description}
                                  </Typography>
                                )}
                                
                                {result.details.meta?.author && (
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Author:</strong> {result.details.meta.author}
                                  </Typography>
                                )}
                                
                                {result.details.meta?.severity && (
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Severity:</strong> {result.details.meta.severity}
                                  </Typography>
                                )}
                                
                                {result.details.strings && result.details.strings.length > 0 && (
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Matched Strings:</strong> {result.details.strings.slice(0, 3).map(s => s[2]).join(', ')}
                                    {result.details.strings.length > 3 && ` (+${result.details.strings.length - 3} more)`}
                                  </Typography>
                                )}
                                
                                {result.details.heuristic && (
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Heuristic:</strong> {result.details.heuristic}
                                  </Typography>
                                )}
                              </Box>
                            )}
                            
                            {threatScore >= 80 && (
                              <Alert severity="error" sx={{ mt: 1 }}>
                                ⚠️ This file has a high threat score and should be quarantined immediately!
                              </Alert>
                            )}
                          </Box>
                        }
                      />
                      <ListItemSecondaryAction>
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                          <Tooltip title={`Quarantine ${result.path.split('/').pop()}`}>
                            <IconButton
                              edge="end"
                              aria-label="quarantine"
                              onClick={() => quarantineFile(result.path)}
                              color={getRiskColor(riskLevel)}
                              sx={{ 
                                bgcolor: getRiskColor(riskLevel) === 'error' ? 'error.light' : 
                                        getRiskColor(riskLevel) === 'warning' ? 'warning.light' : 'grey.100'
                              }}
                            >
                              <DeleteIcon />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </ListItemSecondaryAction>
                    </ListItem>
                  );
                })}
              </List>
              
              {scanResults.filter(result => (result.score || 0) >= 80).length > 0 && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  <Typography variant="body1" fontWeight="bold">
                    🚨 HIGH RISK THREATS DETECTED!
                  </Typography>
                  <Typography variant="body2">
                    {scanResults.filter(result => (result.score || 0) >= 80).length} file(s) with high threat scores (≥80) have been detected. 
                    These files pose a significant security risk and should be quarantined immediately.
                  </Typography>
                </Alert>
              )}
            </Paper>
          </Grid>
        )}
      </Grid>
    </Box>
  );
}

export default ScanCenter; 