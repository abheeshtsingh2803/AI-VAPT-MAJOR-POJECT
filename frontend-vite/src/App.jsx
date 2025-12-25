import React, { useState, useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import axios from "axios";

import LoginForm from "./pages/LoginForm";
import Dashboard from "./pages/Dashboard";
import Scandetails from "./pages/Scandetails";

// Vite env variable
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const App = () => {
  const [token, setToken] = useState(localStorage.getItem("token"));
  const [loading, setLoading] = useState(false);

  // attach token to axios
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
      const res = await axios.post(`${API}/auth/login`, credentials);
      const { access_token } = res.data;

      localStorage.setItem("token", access_token);
      setToken(access_token);
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (data) => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/auth/register`, data);
      const { access_token } = res.data;

      localStorage.setItem("token", access_token);
      setToken(access_token);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="text-white">
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
          element={token ? <Dashboard /> : <Navigate to="/login" />}
        />

        <Route
          path="/scandetails"
          element={token ? <Scandetails /> : <Navigate to="/login" />}
        />

        <Route path="*" element={<Navigate to="/login" />} />
      </Routes>
    </div>
  );
};

export default App;
