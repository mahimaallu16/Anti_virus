import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  List,
  ListItem,
  ListItemText,
  Divider,
} from '@mui/material';
import axios from 'axios';

function Dashboard() {
  const [systemMetrics, setSystemMetrics] = useState({
    cpu: 0,
    ram: 0,
    disk: 0,
  });
  const [activityLog, setActivityLog] = useState([]);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const response = await axios.get('http://localhost:8000/api/metrics');
        setSystemMetrics(response.data);
      } catch (error) {
        console.error('Error fetching metrics:', error);
      }
    };

    const fetchActivityLog = async () => {
      try {
        const response = await axios.get('http://localhost:8000/api/logs');
        setActivityLog(response.data);
      } catch (error) {
        console.error('Error fetching activity log:', error);
      }
    };

    fetchMetrics();
    fetchActivityLog();

    const interval = setInterval(() => {
      fetchMetrics();
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const MetricCard = ({ title, value, unit }) => (
    <Paper
      elevation={3}
      sx={{
        p: 2,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        height: '100%',
      }}
    >
      <Typography variant="h6" gutterBottom>
        {title}
      </Typography>
      <Typography variant="h4" color="primary">
        {value}
        {unit}
      </Typography>
    </Paper>
  );

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <MetricCard
            title="CPU Usage"
            value={systemMetrics.cpu}
            unit="%"
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <MetricCard
            title="RAM Usage"
            value={systemMetrics.ram}
            unit="%"
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <MetricCard
            title="Disk Usage"
            value={systemMetrics.disk}
            unit="%"
          />
        </Grid>
        <Grid item xs={12}>
          <Paper elevation={3} sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Activity Log
            </Typography>
            <List>
              {activityLog.map((log, index) => (
                <React.Fragment key={index}>
                  <ListItem>
                    <ListItemText
                      primary={log.message}
                      secondary={new Date(log.timestamp).toLocaleString()}
                    />
                  </ListItem>
                  {index < activityLog.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard; 