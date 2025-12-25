import React, { useState, useEffect } from "react";
import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  Plus,
  LogOut,
  Eye,
  RefreshCw,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "react-hot-toast";

// Vite env
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = ({ onLogout }) => {
  const navigate = useNavigate();

  const [statistics, setStatistics] = useState({
    total_scans: 0,
    completed_scans: 0,
    total_vulnerabilities: 0,
    high_risk_count: 0,
    medium_risk_count: 0,
    low_risk_count: 0,
  });

  const [scans, setScans] = useState([]);
  const [showNewScanModal, setShowNewScanModal] = useState(false);
  const [newScanUrl, setNewScanUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      const [statsRes, scansRes] = await Promise.all([
        axios.get(`${API}/dashboard/statistics`),
        axios.get(`${API}/scans`),
      ]);

      setStatistics(statsRes.data);
      setScans(scansRes.data);
    } catch {
      toast.error("Failed to load dashboard data");
    }
  };

  const refreshData = async () => {
    setRefreshing(true);
    await loadDashboardData();
    setRefreshing(false);
    toast.success("Data refreshed");
  };

  const handleNewScan = async (e) => {
    e.preventDefault();
    if (!newScanUrl.trim()) return;

    setLoading(true);
    try {
      toast.loading("Starting vulnerability scan...", { id: "scan" });

      await axios.post(`${API}/scans/start`, {
        target_url: newScanUrl,
        scan_type: "web_app",
      });

      toast.success("Scan started successfully", { id: "scan" });
      setShowNewScanModal(false);
      setNewScanUrl("");
      setTimeout(loadDashboardData, 1000);
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to start scan", {
        id: "scan",
      });
    } finally {
      setLoading(false);
    }
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

  return (
    <div className="min-h-screen">
      {/* Navbar */}
      <nav className="navbar">
        <div className="navbar-content">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6" />
            VAPT Platform
          </div>

          <div className="flex gap-3">
            <button
              onClick={refreshData}
              className="btn btn-secondary"
              disabled={refreshing}
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
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-white">
              Security Dashboard
            </h1>
            <p className="text-gray-400">
              Monitor and manage vulnerability assessments
            </p>
          </div>

          <button
            onClick={() => setShowNewScanModal(true)}
            className="btn btn-primary"
          >
            <Plus className="w-4 h-4" />
            New Scan
          </button>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard
            icon={Search}
            label="Total Scans"
            value={statistics.total_scans}
            // value="0"
            color="blue"
          />
          <StatCard
            icon={CheckCircle}
            label="Completed"
            value={statistics.completed_scans}
            color="green"
            // value="0"
          />
          <StatCard
            icon={AlertTriangle}
            label="Vulnerabilities"
            value={statistics.total_vulnerabilities}
            // value="0"
            color="red"
          />
          <StatCard
            icon={TrendingUp}
            label="High Risk"
            value={statistics.high_risk_count}
            // value="0"
            color="orange"
          />
        </div>

        {/* Recent Scans */}
        <div className="h-max card">
          <h2 className="text-xl font-semibold text-white mb-6">Recent Scans</h2>
          
          {scans.length === 0 ? (
            <div className="text-center py-12" data-testid="no-scans-message">
              <div className="flex justify-center">
                <Search className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              </div>
              <h3 className="text-lg font-medium text-gray-400 mb-2">No scans yet</h3>
              <p className="text-gray-500 mb-4">Start your first vulnerability assessment</p>
              <button
                onClick={() => setShowNewScanModal(true)}
                className="btn btn-primary"
              >
                <Plus className="w-4 h-4" />
                Start First Scan
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full" data-testid="scans-table">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 text-gray-400 font-medium">Target</th>
                    <th className="text-left py-3 text-gray-400 font-medium">Status</th>
                    <th className="text-left py-3 text-gray-400 font-medium">Vulnerabilities</th>
                    <th className="text-left py-3 text-gray-400 font-medium">Risk Distribution</th>
                    <th className="text-left py-3 text-gray-400 font-medium">Date</th>
                    <th className="text-left py-3 text-gray-400 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan) => (
                    <tr key={scan.id} className="border-b border-gray-800 hover:bg-gray-800/50">
                      <td className="py-4">
                        <div className="truncate max-w-xs" title={scan.target_url}>
                          {scan.target_url}
                        </div>
                      </td>
                      <td className="py-4">
                        <span className={getStatusBadge(scan.status)}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="py-4 text-white font-medium">
                        {scan.total_vulnerabilities}
                      </td>
                      <td className="py-4">
                        <div className="flex gap-1">
                          {scan.high_risk > 0 && (
                            <span className="px-2 py-1 text-xs rounded bg-red-500/20 text-red-400">
                              H: {scan.high_risk}
                            </span>
                          )}
                          {scan.medium_risk > 0 && (
                            <span className="px-2 py-1 text-xs rounded bg-yellow-500/20 text-yellow-400">
                              M: {scan.medium_risk}
                            </span>
                          )}
                          {scan.low_risk > 0 && (
                            <span className="px-2 py-1 text-xs rounded bg-green-500/20 text-green-400">
                              L: {scan.low_risk}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-4 text-gray-400 text-sm">
                        {formatDate(scan.created_at)}
                      </td>
                      <td className="py-4">
                        <button
                          onClick={() => navigate(`/scan/${scan.id}`)}
                          className="btn btn-secondary text-sm"
                          data-testid={`view-scan-${scan.id}`}
                        >
                          <Eye className="w-4 h-4" />
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* New Scan Modal */}
      {showNewScanModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center">
          <div className="card max-w-md w-full">
            <h3 className="text-xl font-semibold mb-4">
              Start New Scan
            </h3>

            <form onSubmit={handleNewScan} className="space-y-4">
              <input
                type="url"
                value={newScanUrl}
                onChange={(e) => setNewScanUrl(e.target.value)}
                className="form-input"
                placeholder="https://example.com"
                required
              />

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => setShowNewScanModal(false)}
                  className="btn btn-secondary flex-1"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="btn btn-primary flex-1"
                >
                  {loading ? "Starting..." : "Start Scan"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

const COLORS = {
  blue: "bg-blue-500/20 text-blue-400",
  green: "bg-green-500/20 text-green-400",
  red: "bg-red-500/20 text-red-400",
  orange: "bg-orange-500/20 text-orange-400",
};

const StatCard = ({ icon: Icon, label, value, color = "blue" }) => (
  <div className="card">
    <div className="flex items-center gap-4">
      <div className={`"size-10 p-4 flex items-center justify-center rounded-lg " ${COLORS[color]}`}>
        <Icon className="w-8 h-8" />
      </div>
      <div>
        <p className="text-sm text-gray-400">{label}</p>
        <p className="text-2xl font-bold text-white">{value}</p>
      </div>
    </div>
  </div>
);


export default Dashboard;
