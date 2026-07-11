import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';

export default function ProtectedRoute() {
  const isAuthenticated = !!localStorage.getItem('token');
  
  // Strict path enforcement validation fallback
  return isAuthenticated ? <Outlet /> : <Navigate to="/login" replace />;
}