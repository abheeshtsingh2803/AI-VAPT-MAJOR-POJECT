import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  ExternalLink,
  Download,
  RefreshCw,
  LogOut,
  Brain,
  Target,
  Bug
} from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-hot-toast';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
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
    const interval = setInterval(loadScanDetails, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, [scanId]);

  const loadScanDetails = async (retryCount = 0) => {
    try {
      const [scansResponse, vulnerabilitiesResponse] = await Promise.all([
        axios.get(`${API}/scans`),
        axios.get(`${API}/scans/${scanId}/vulnerabilities`)
      ]);
      
      const scanData = scansResponse.data.find(s => s.id === scanId);
      if (!scanData && retryCount < 2) {
        // Retry after 1 second if scan not found
        setTimeout(() => loadScanDetails(retryCount + 1), 1000);
        return;
      }
      
      setScan(scanData);
      setVulnerabilities(vulnerabilitiesResponse.data);
    } catch (error) {
      if (retryCount < 2) {
        // Retry after 2 seconds on error
        setTimeout(() => loadScanDetails(retryCount + 1), 2000);
        return;
      }
      toast.error('Failed to load scan details');
      console.error('Scan details loading error:', error);
    } finally {
      setLoading(false);
    }
  };

  const refreshData = async () => {
    setRefreshing(true);
    await loadScanDetails();
    setRefreshing(false);
    toast.success('Data refreshed');
  };

  const getSeverityBadge = (severity) => {
    const classes = {
      'Critical': 'badge severity-critical',
      'High': 'badge severity-high',
      'Medium': 'badge severity-medium',
      'Low': 'badge severity-low'
    };
    return classes[severity] || 'badge';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'border-l-red-500 bg-red-500/10',
      'High': 'border-l-orange-500 bg-orange-500/10',
      'Medium': 'border-l-yellow-500 bg-yellow-500/10',
      'Low': 'border-l-green-500 bg-green-500/10'
    };
    return colors[severity] || 'border-l-gray-500 bg-gray-500/10';
  };

  const getStatusBadge = (status) => {
    const badges = {
      'pending': 'badge badge-info',
      'running': 'badge badge-warning',
      'completed': 'badge badge-success',
      'failed': 'badge badge-danger'
    };
    return badges[status] || 'badge';
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  if (loading) {
    return (
      <div className="min-h-screen">
        {/* Navigation */}
        <nav className="navbar">
          <div className="navbar-content">
            <div className="flex items-center gap-4">
              <button
                onClick={() => navigate('/dashboard')}
                className="btn btn-secondary"
                data-testid="back-to-dashboard"
              >
                <ArrowLeft className="w-4 h-4" />
                Dashboard
              </button>
              <div className="navbar-brand flex items-center gap-2">
                <Shield className="w-6 h-6" />
                Loading Scan...
              </div>
            </div>
          </div>
        </nav>
        
        <div className="flex items-center justify-center" style={{height: 'calc(100vh - 80px)'}}>
          <div className="text-center">
            <div className="spinner mx-auto mb-4" style={{width: '40px', height: '40px'}}></div>
            <p className="text-gray-400">Loading scan details...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="w-16 h-16 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Scan Not Found</h2>
          <p className="text-gray-400 mb-4">The requested scan could not be found.</p>
          <button onClick={() => navigate('/dashboard')} className="btn btn-primary">
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      {/* Navigation */}
      <nav className="navbar">
        <div className="navbar-content">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/dashboard')}
              className="btn btn-secondary"
              data-testid="back-to-dashboard"
            >
              <ArrowLeft className="w-4 h-4" />
              Dashboard
            </button>
            <div className="navbar-brand flex items-center gap-2">
              <Shield className="w-6 h-6" />
              Scan Details
            </div>
          </div>
          
          <div className="navbar-nav">
            <button
              onClick={refreshData}
              className="btn btn-secondary"
              disabled={refreshing}
              data-testid="refresh-scan-button"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
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
        {/* Scan Overview */}
        <div className="card mb-8" data-testid="scan-overview">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between mb-6">
            <div>
              <h1 className="text-3xl font-bold text-white mb-2">
                Vulnerability Assessment Report
              </h1>
              <div className="flex items-center gap-4 text-sm text-gray-400">
                <span className="flex items-center gap-1">
                  <Target className="w-4 h-4" />
                  {scan.target_url}
                </span>
                <span>Scan ID: {scan.id.slice(0, 8)}</span>
              </div>
            </div>
            
            <div className="flex items-center gap-4 mt-4 lg:mt-0">
              <span className={getStatusBadge(scan.status)} data-testid="scan-status">
                {scan.status}
              </span>
              {scan.status === 'running' && (
                <div className="flex items-center gap-2 text-blue-400">
                  <div className="spinner" style={{width: '16px', height: '16px'}}></div>
                  <span>Scanning in progress...</span>
                </div>
              )}
            </div>
          </div>

          {/* Scan Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-800/50 rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-white mb-1" data-testid="scan-total-vulnerabilities">
                {scan.total_vulnerabilities}
              </div>
              <div className="text-sm text-gray-400">Total Vulnerabilities</div>
            </div>
            <div className="bg-red-500/10 rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-red-400 mb-1" data-testid="scan-high-risk">
                {scan.high_risk}
              </div>
              <div className="text-sm text-gray-400">High Risk</div>
            </div>
            <div className="bg-yellow-500/10 rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-yellow-400 mb-1" data-testid="scan-medium-risk">
                {scan.medium_risk}
              </div>
              <div className="text-sm text-gray-400">Medium Risk</div>
            </div>
            <div className="bg-green-500/10 rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-green-400 mb-1" data-testid="scan-low-risk">
                {scan.low_risk}
              </div>
              <div className="text-sm text-gray-400">Low Risk</div>
            </div>
          </div>

          {/* Scan Timeline */}
          <div className="text-sm text-gray-400 space-y-1">
            <div>Started: {formatDate(scan.created_at)}</div>
            {scan.completed_at && (
              <div>Completed: {formatDate(scan.completed_at)}</div>
            )}
          </div>
        </div>

        {/* AI Analysis */}
        {scan.ai_summary && (
          <div className="card mb-8" data-testid="ai-analysis">
            <div className="flex items-center gap-2 mb-4">
              <Brain className="w-5 h-5 text-purple-400" />
              <h2 className="text-xl font-semibold text-white">AI Security Analysis</h2>
            </div>
            <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4">
              <pre className="whitespace-pre-wrap text-gray-300 text-sm leading-relaxed">
                {scan.ai_summary}
              </pre>
            </div>
          </div>
        )}

        {/* Vulnerabilities List */}
        <div className="card">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-white flex items-center gap-2">
              <Bug className="w-5 h-5" />
              Vulnerabilities ({vulnerabilities.length})
            </h2>
          </div>

          {vulnerabilities.length === 0 ? (
            <div className="text-center py-12" data-testid="no-vulnerabilities-message">
              {scan.status === 'completed' ? (
                <>
                  <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-green-400 mb-2">No Vulnerabilities Found</h3>
                  <p className="text-gray-400">The target appears to be secure based on our assessment.</p>
                </>
              ) : (
                <>
                  <Clock className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-400 mb-2">Scan In Progress</h3>
                  <p className="text-gray-500">Vulnerabilities will appear here as they are discovered.</p>
                </>
              )}
            </div>
          ) : (
            <div className="space-y-4" data-testid="vulnerabilities-list">
              {vulnerabilities.map((vulnerability) => (
                <div
                  key={vulnerability.id}
                  className={`border-l-4 rounded-lg p-4 cursor-pointer transition-colors hover:bg-gray-800/30 ${getSeverityColor(vulnerability.severity)}`}
                  onClick={() => setSelectedVulnerability(vulnerability)}
                  data-testid={`vulnerability-${vulnerability.id}`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-semibold text-white">{vulnerability.title}</h3>
                        <span className={getSeverityBadge(vulnerability.severity)}>
                          {vulnerability.severity}
                        </span>
                        <span className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded">
                          CVSS: {vulnerability.cvss_score}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm mb-2">{vulnerability.description}</p>
                      <div className="text-xs text-gray-500 truncate">
                        Location: {vulnerability.location}
                      </div>
                    </div>
                    <ExternalLink className="w-4 h-4 text-gray-400 ml-4 flex-shrink-0" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Vulnerability Detail Modal */}
      {selectedVulnerability && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="card max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold text-white">Vulnerability Details</h3>
              <button
                onClick={() => setSelectedVulnerability(null)}
                className="text-gray-400 hover:text-white"
                data-testid="close-vulnerability-modal"
              >
                ×
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <h4 className="font-semibold text-white">{selectedVulnerability.title}</h4>
                  <span className={getSeverityBadge(selectedVulnerability.severity)}>
                    {selectedVulnerability.severity}
                  </span>
                </div>
                <div className="text-sm text-gray-400 mb-2">
                  <strong>Type:</strong> {selectedVulnerability.vulnerability_type}
                </div>
                <div className="text-sm text-gray-400 mb-4">
                  <strong>CVSS Score:</strong> {selectedVulnerability.cvss_score}/10.0
                </div>
              </div>

              <div>
                <h5 className="font-medium text-white mb-2">Description</h5>
                <p className="text-gray-300 text-sm">{selectedVulnerability.description}</p>
              </div>

              <div>
                <h5 className="font-medium text-white mb-2">Location</h5>
                <code className="block bg-gray-800 p-3 rounded text-sm text-gray-300 break-all">
                  {selectedVulnerability.location}
                </code>
              </div>

              <div>
                <h5 className="font-medium text-white mb-2">Recommendation</h5>
                <p className="text-gray-300 text-sm">{selectedVulnerability.recommendation}</p>
              </div>

              {selectedVulnerability.ai_analysis && (
                <div>
                  <h5 className="font-medium text-white mb-2 flex items-center gap-2">
                    <Brain className="w-4 h-4 text-purple-400" />
                    AI Analysis
                  </h5>
                  <div className="bg-purple-500/10 border border-purple-500/20 rounded p-3">
                    <p className="text-gray-300 text-sm">{selectedVulnerability.ai_analysis}</p>
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setSelectedVulnerability(null)}
                className="btn btn-secondary"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanDetails;