import React, { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import axios from "axios";
import { Toaster, toast } from "react-hot-toast";
import "./App.css";

// Components
import LoginForm from "./components/LoginForm";
import Dashboard from "./components/Dashboard";
import ScanDetails from "./components/ScanDetails";

// ✅ Vite environment variable
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Set up axios defaults
axios.defaults.headers.common["Content-Type"] = "application/json";

function App() {
  const [token, setToken] = useState(localStorage.getItem("token"));
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
    } else {
      delete axios.defaults.headers.common["Authorization"];
    }
  }, [token]);

  const handleLogin = async (credentials) => {
    setLoading(true);
    try {
      const response = await axios.post(`${API}/auth/login`, credentials);
      const { access_token } = response.data;

      setToken(access_token);
      localStorage.setItem("token", access_token);
      axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`;

      toast.success("Login successful!");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Login failed");
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (userData) => {
    setLoading(true);
    try {
      const response = await axios.post(`${API}/auth/register`, userData);
      const { access_token } = response.data;

      setToken(access_token);
      localStorage.setItem("token", access_token);
      axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`;

      toast.success("Registration successful!");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Registration failed");
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem("token");
    delete axios.defaults.headers.common["Authorization"];
    toast.success("Logged out successfully");
  };

  const ProtectedRoute = ({ children }) => {
    return token ? children : <Navigate to="/login" replace />;
  };

  return (
    <div className="App">
      <Toaster position="top-right" />

      <BrowserRouter>
        <Routes>
          <Route
            path="/login"
            element={
              token ? (
                <Navigate to="/dashboard" replace />
              ) : (
                <LoginForm
                  onLogin={handleLogin}
                  onRegister={handleRegister}
                  loading={loading}
                />
              )
            }
          />

          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard onLogout={handleLogout} />
              </ProtectedRoute>
            }
          />

          <Route
            path="/scan/:scanId"
            element={
              <ProtectedRoute>
                <ScanDetails onLogout={handleLogout} />
              </ProtectedRoute>
            }
          />

          <Route
            path="/"
            element={
              <Navigate to={token ? "/dashboard" : "/login"} replace />
            }
          />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;
