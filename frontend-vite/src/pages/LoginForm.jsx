import React, { useState } from "react";
import {
  Shield,
  User,
  Mail,
  Lock,
  Eye,
  EyeOff,
} from "lucide-react";

const LoginForm = ({ onLogin, onRegister, loading }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
  });

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

const handleSubmit = async (e) => {
  e.preventDefault();

  if (isLogin) {
    await onLogin?.({
      username: formData.username,
      password: formData.password,
    });
  } else {
    if (!onRegister) {
      console.error("onRegister prop not provided");
      return;
    }
    await onRegister(formData);
  }
};

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        <div className="card">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="flex items-center justify-center mb-4">
              <div className="p-4 rounded-full bg-gradient-to-r from-blue-500 to-purple-600">
                <Shield className="w-8 h-8 text-white" />
              </div>
            </div>
            <h1 className="text-3xl font-bold text-white mb-2">
              VAPT Platform
            </h1>
            <p className="text-gray-400">
              AI-Powered Vulnerability Assessment & Penetration Testing
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">
                <User className="p-2 w-4 h-4 inline" />
                Username
              </label>
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleChange}
                className="form-input"
                placeholder="Enter your username"
                required
              />
            </div>

            {!isLogin && (
              <div className="form-group">
                <label className="form-label">
                  <Mail className="w-4 h-4 inline mr-2" />
                  Email
                </label>
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  className="form-input"
                  placeholder="Enter your email"
                  required
                />
              </div>
            )}

            <div className="form-group">
              <label className="form-label">
                <Lock className="w-4 h-4 inline mr-2" />
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  className="form-input pr-10"
                  placeholder="Enter your password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showPassword ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={
                loading ||
                !formData.username ||
                !formData.password ||
                (!isLogin && !formData.email)
              }
              className="btn btn-primary w-full mb-4 text-white"
            >
              {loading
                ? isLogin
                  ? "Logging in..."
                  : "Creating account..."
                : isLogin
                ? "Sign In"
                : "Create Account"}
            </button>
          </form>

          {/* Toggle */}
          <div className="mt-6 text-center">
            <p className="text-gray-400">
              {isLogin
                ? "Don't have an account?"
                : "Already have an account?"}
            </p>
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin);
                setFormData({ username: "", email: "", password: "" });
              }}
              className="text-blue-400 hover:text-blue-300 font-medium mt-2"
            >
              {isLogin ? "Create Account" : "Sign In"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginForm;
