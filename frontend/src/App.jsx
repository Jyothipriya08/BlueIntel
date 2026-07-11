import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Landing from './pages/landing';
import Dashboard from './pages/dashboard';
import Settings from './pages/settings';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Intro Landing UI */}
        <Route path="/" element={<Landing />} />
        
        {/* Core Console Dashboards */}
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/settings" element={<Settings />} />

        {/* Redirection fallback */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}