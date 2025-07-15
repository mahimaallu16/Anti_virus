import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Dashboard from './components/Dashboard';
import ScanCenter from './components/ScanCenter';
import Quarantine from './components/Quarantine';
import RealTimeProtection from './components/RealTimeProtection';
import Layout from './components/Layout';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#0078d4',
    },
    secondary: {
      main: '#1a252f',
    },
    background: {
      default: '#f5f6f5',
    },
  },
  typography: {
    fontFamily: '"Segoe UI", sans-serif',
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<ScanCenter />} />
            <Route path="/quarantine" element={<Quarantine />} />
            <Route path="/protection" element={<RealTimeProtection />} />
          </Routes>
        </Layout>
      </Router>
    </ThemeProvider>
  );
}

export default App; 