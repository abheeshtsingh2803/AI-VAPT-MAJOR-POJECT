import React, { useState, useEffect } from "react";
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  ExternalLink,
  RefreshCw,
  LogOut,
  Brain,
  Target,
  Bug,
} from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";
import axios from "axios";
import { toast } from "react-hot-toast";

// ✅ Vite environment variable
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const ScanDetails = ({ onLogout }) => {
  const navigate = useNavigate();
  const { scanId } = useParams();

  const [scan, setScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);

  useEffect(() => {
    loadScanDetails();
    const interval = setInterval(loadScanDetails, 10000);
    return () => clearInterval(interval);
  }, [scanId]);

  const loadScanDetails = async (retryCount = 0) => {
    try {
      const [scansRes, vulnsRes] = await Promise.all([
        axios.get(`${API}/scans`),
        axios.get(`${API}/scans/${scanId}/vulnerabilities`),
      ]);

      const scanData = scansRes.data.find(
        (s) => String(s.id) === String(scanId)
      );

      if (!scanData && retryCount < 2) {
        setTimeout(() => loadScanDetails(retryCount + 1), 1000);
        return;
      }

      setScan(scanData);
      setVulnerabilities(vulnsRes.data);
    } catch (error) {
      if (retryCount < 2) {
        setTimeout(() => loadScanDetails(retryCount + 1), 2000);
        return;
      }
      toast.error("Failed to load scan details");
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const refreshData = async () => {
    setRefreshing(true);
    await loadScanDetails();
    setRefreshing(false);
    toast.success("Data refreshed");
  };

  const getSeverityBadge = (severity) => {
    const map = {
      Critical: "badge severity-critical",
      High: "badge severity-high",
      Medium: "badge severity-medium",
      Low: "badge severity-low",
    };
    return map[severity] || "badge";
  };

  const getSeverityColor = (severity) => {
    const map = {
      Critical: "border-l-red-500 bg-red-500/10",
      High: "border-l-orange-500 bg-orange-500/10",
      Medium: "border-l-yellow-500 bg-yellow-500/10",
      Low: "border-l-green-500 bg-green-500/10",
    };
    return map[severity] || "border-l-gray-500 bg-gray-500/10";
  };

  const getStatusBadge = (status) => {
    const map = {
      pending: "badge badge-info",
      running: "badge badge-warning",
      completed: "badge badge-success",
      failed: "badge badge-danger",
    };
    return map[status] || "badge";
  };

  const formatDate = (date) => new Date(date).toLocaleString();

  /* -------------------- LOADING STATE -------------------- */
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="spinner mx-auto mb-4 w-10 h-10" />
          <p className="text-gray-400">Loading scan details...</p>
        </div>
      </div>
    );
  }

  /* -------------------- NOT FOUND -------------------- */
  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="flex justify-center">
            <AlertTriangle className="w-16 h-16 text-red-400 mx-auto mb-4" />
          </div>
          <h2 className="text-xl font-bold text-white mb-2">
            Scan Not Found
          </h2>
          <button
            onClick={() => navigate("/dashboard")}
            className="btn btn-primary"
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  /* -------------------- MAIN UI -------------------- */
  return (
    <div className="min-h-screen">
      {/* Navbar */}
      <nav className="navbar">
        <div className="navbar-content">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate("/dashboard")}
              className="btn btn-secondary"
            >
              <ArrowLeft className="w-4 h-4" />
              Dashboard
            </button>
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6" />
              Scan Details
            </div>
          </div>

          <div className="flex gap-3">
            <button
              onClick={refreshData}
              disabled={refreshing}
              className="btn btn-secondary"
            >
              <RefreshCw
                className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
            <button onClick={onLogout} className="btn btn-secondary">
              <LogOut className="w-4 h-4" />
              Logout
            </button>
          </div>
        </div>
      </nav>

      <div className="container py-8">
        {/* Overview */}
        <div className="card mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">
            Vulnerability Assessment Report
          </h1>
          <div className="flex items-center gap-4 text-sm text-gray-400">
            <span className="flex items-center gap-1">
              <Target className="w-4 h-4" />
              {scan.target_url}
            </span>
            <span>Scan ID: {scan.id.slice(0, 8)}</span>
            <span className={getStatusBadge(scan.status)}>
              {scan.status}
            </span>
          </div>
        </div>

        {/* Vulnerabilities */}
        <div className="card">
          <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
            <Bug className="w-5 h-5" />
            Vulnerabilities ({vulnerabilities.length})
          </h2>

          {vulnerabilities.length === 0 ? (
            <p className="text-gray-400 text-center py-8">
              No vulnerabilities detected yet
            </p>
          ) : (
            <div className="space-y-4">
              {vulnerabilities.map((v) => (
                <div
                  key={v.id}
                  className={`border-l-4 rounded-lg p-4 cursor-pointer ${getSeverityColor(
                    v.severity
                  )}`}
                  onClick={() => setSelectedVulnerability(v)}
                >
                  <div className="flex justify-between">
                    <div>
                      <div className="flex gap-2 mb-1">
                        <h3 className="font-semibold text-white">
                          {v.title}
                        </h3>
                        <span className={getSeverityBadge(v.severity)}>
                          {v.severity}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm">
                        {v.description}
                      </p>
                    </div>
                    <ExternalLink className="w-4 h-4 text-gray-400" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Vulnerability Modal */}
      {selectedVulnerability && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4">
          <div className="card max-w-2xl w-full">
            <h3 className="text-xl font-semibold text-white mb-4">
              {selectedVulnerability.title}
            </h3>
            <p className="text-gray-300 text-sm mb-4">
              {selectedVulnerability.description}
            </p>
            <button
              onClick={() => setSelectedVulnerability(null)}
              className="btn btn-secondary"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanDetails;
