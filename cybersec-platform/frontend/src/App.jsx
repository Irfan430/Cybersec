import React, { Suspense, lazy } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from 'react-query'
import { ReactQueryDevtools } from 'react-query/devtools'
import { Toaster } from 'react-hot-toast'
import { HelmetProvider } from 'react-helmet-async'
import { ErrorBoundary } from 'react-error-boundary'

// Contexts
import { AuthProvider } from '@contexts/AuthContext'
import { ThemeProvider } from '@contexts/ThemeContext'
import { SocketProvider } from '@contexts/SocketContext'
import { NotificationProvider } from '@contexts/NotificationContext'

// Components
import LoadingSpinner from '@components/ui/LoadingSpinner'
import ErrorFallback from '@components/ui/ErrorFallback'
import ProtectedRoute from '@components/auth/ProtectedRoute'
import Layout from '@components/layout/Layout'
import AuthLayout from '@components/layout/AuthLayout'

// Lazy load pages for better performance
const Dashboard = lazy(() => import('@pages/Dashboard'))
const Login = lazy(() => import('@pages/auth/Login'))
const Register = lazy(() => import('@pages/auth/Register'))
const ForgotPassword = lazy(() => import('@pages/auth/ForgotPassword'))
const ResetPassword = lazy(() => import('@pages/auth/ResetPassword'))
const EmailVerification = lazy(() => import('@pages/auth/EmailVerification'))

// Main application pages
const Targets = lazy(() => import('@pages/Targets'))
const Scans = lazy(() => import('@pages/Scans'))
const ScanResults = lazy(() => import('@pages/ScanResults'))
const Reports = lazy(() => import('@pages/Reports'))
const Vulnerabilities = lazy(() => import('@pages/Vulnerabilities'))
const ThreatIntelligence = lazy(() => import('@pages/ThreatIntelligence'))
const Phishing = lazy(() => import('@pages/Phishing'))
const BruteForce = lazy(() => import('@pages/BruteForce'))
const Compliance = lazy(() => import('@pages/Compliance'))
const Analytics = lazy(() => import('@pages/Analytics'))
const Alerts = lazy(() => import('@pages/Alerts'))
const Settings = lazy(() => import('@pages/Settings'))
const Users = lazy(() => import('@pages/Users'))
const Billing = lazy(() => import('@pages/Billing'))
const ApiDocs = lazy(() => import('@pages/ApiDocs'))
const Profile = lazy(() => import('@pages/Profile'))
const Help = lazy(() => import('@pages/Help'))
const About = lazy(() => import('@pages/About'))
const NotFound = lazy(() => import('@pages/NotFound'))

// Audit and monitoring pages
const AuditLogs = lazy(() => import('@pages/AuditLogs'))
const SystemHealth = lazy(() => import('@pages/SystemHealth'))
const Performance = lazy(() => import('@pages/Performance'))

// Training and simulation pages
const TrainingModule = lazy(() => import('@pages/TrainingModule'))
const SimulationLab = lazy(() => import('@pages/SimulationLab'))
const KnowledgeBase = lazy(() => import('@pages/KnowledgeBase'))

// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      retry: (failureCount, error) => {
        if (error.status === 401 || error.status === 403) {
          return false
        }
        return failureCount < 3
      },
      refetchOnWindowFocus: false,
      refetchOnMount: true,
      refetchOnReconnect: true
    },
    mutations: {
      retry: false
    }
  }
})

// Main App component
function App() {
  return (
    <ErrorBoundary
      FallbackComponent={ErrorFallback}
      onReset={() => window.location.reload()}
    >
      <HelmetProvider>
        <QueryClientProvider client={queryClient}>
          <ThemeProvider>
            <AuthProvider>
              <NotificationProvider>
                <SocketProvider>
                  <Router>
                    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
                      <Suspense fallback={<LoadingSpinner />}>
                        <Routes>
                          {/* Public routes */}
                          <Route path="/auth/*" element={<AuthLayout />}>
                            <Route path="login" element={<Login />} />
                            <Route path="register" element={<Register />} />
                            <Route path="forgot-password" element={<ForgotPassword />} />
                            <Route path="reset-password" element={<ResetPassword />} />
                            <Route path="verify-email" element={<EmailVerification />} />
                          </Route>

                          {/* Protected routes */}
                          <Route path="/" element={
                            <ProtectedRoute>
                              <Layout />
                            </ProtectedRoute>
                          }>
                            {/* Main dashboard */}
                            <Route index element={<Dashboard />} />
                            
                            {/* Target management */}
                            <Route path="targets" element={<Targets />} />
                            
                            {/* Scanning */}
                            <Route path="scans" element={<Scans />} />
                            <Route path="scans/:scanId" element={<ScanResults />} />
                            
                            {/* Security assessments */}
                            <Route path="vulnerabilities" element={<Vulnerabilities />} />
                            <Route path="threat-intelligence" element={<ThreatIntelligence />} />
                            <Route path="brute-force" element={<BruteForce />} />
                            <Route path="compliance" element={<Compliance />} />
                            
                            {/* Reports and analytics */}
                            <Route path="reports" element={<Reports />} />
                            <Route path="analytics" element={<Analytics />} />
                            
                            {/* Training and simulation */}
                            <Route path="phishing" element={<Phishing />} />
                            <Route path="training" element={<TrainingModule />} />
                            <Route path="simulation" element={<SimulationLab />} />
                            <Route path="knowledge-base" element={<KnowledgeBase />} />
                            
                            {/* Monitoring and alerts */}
                            <Route path="alerts" element={<Alerts />} />
                            <Route path="audit-logs" element={<AuditLogs />} />
                            <Route path="system-health" element={<SystemHealth />} />
                            <Route path="performance" element={<Performance />} />
                            
                            {/* User management */}
                            <Route path="users" element={<Users />} />
                            <Route path="profile" element={<Profile />} />
                            
                            {/* Billing and subscription */}
                            <Route path="billing" element={<Billing />} />
                            
                            {/* System */}
                            <Route path="settings" element={<Settings />} />
                            <Route path="api-docs" element={<ApiDocs />} />
                            <Route path="help" element={<Help />} />
                            <Route path="about" element={<About />} />
                          </Route>

                          {/* Fallback routes */}
                          <Route path="/404" element={<NotFound />} />
                          <Route path="*" element={<Navigate to="/404" replace />} />
                        </Routes>
                      </Suspense>
                    </div>
                  </Router>
                  
                  {/* Global toast notifications */}
                  <Toaster
                    position="top-right"
                    reverseOrder={false}
                    gutter={8}
                    containerClassName=""
                    containerStyle={{}}
                    toastOptions={{
                      duration: 4000,
                      style: {
                        background: '#363636',
                        color: '#fff',
                      },
                      success: {
                        duration: 3000,
                        theme: {
                          primary: 'green',
                          secondary: 'black',
                        },
                      },
                      error: {
                        duration: 5000,
                        theme: {
                          primary: 'red',
                          secondary: 'black',
                        },
                      },
                    }}
                  />
                </SocketProvider>
              </NotificationProvider>
            </AuthProvider>
          </ThemeProvider>
          
          {/* React Query DevTools in development */}
          {process.env.NODE_ENV === 'development' && (
            <ReactQueryDevtools initialIsOpen={false} />
          )}
        </QueryClientProvider>
      </HelmetProvider>
    </ErrorBoundary>
  )
}

export default App