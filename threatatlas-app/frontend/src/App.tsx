import { BrowserRouter, Routes, Route, useLocation, Navigate } from 'react-router-dom';
import { SidebarProvider, SidebarInset, SidebarTrigger } from '@/components/ui/sidebar';
import AppSidebar from '@/components/Sidebar';
import Dashboard from '@/pages/Dashboard';
import Products from '@/pages/Products';
import ProductDetails from '@/pages/ProductDetails';
import Diagrams from '@/pages/Diagrams';
import KnowledgeBase from '@/pages/KnowledgeBase';
import Analytics from '@/pages/Analytics';
import Reports from '@/pages/Reports';
import PentestDetail from '@/pages/PentestDetail';
import MyPentests from '@/pages/MyPentests';
import Login from '@/pages/Login';
import AcceptInvitation from '@/pages/AcceptInvitation';
import UserManagement from '@/pages/UserManagement';
import { Separator } from '@/components/ui/separator';
import { Shield } from 'lucide-react';
import { AuthProvider, useAuth } from '@/contexts/AuthContext';
import { ProtectedRoute } from '@/components/ProtectedRoute';

function HeaderBreadcrumb() {
  const location = useLocation();

  const getPageInfo = () => {
    if (location.pathname.startsWith('/products/')) {
      return { title: 'Product Details', subtitle: 'Security analysis & overview' };
    }
    if (location.pathname.startsWith('/pentests/') && location.pathname !== '/pentests/') {
      return { title: 'Pentest Detail', subtitle: 'Penetration test findings & analysis' };
    }
    switch (location.pathname) {
      case '/': return { title: 'Dashboard', subtitle: 'Threat monitoring overview' };
      case '/products': return { title: 'Products', subtitle: 'Manage security products' };
      case '/diagrams': return { title: 'Diagrams', subtitle: 'Threat modeling canvas' };
      case '/knowledge': return { title: 'Knowledge Base', subtitle: 'Threats & mitigations' };
      case '/analytics': return { title: 'Analytics', subtitle: 'Threat analytics & insights' };
      case '/reports': return { title: 'Reports', subtitle: 'Generate threat model reports' };
      case '/users': return { title: 'User Management', subtitle: 'Manage users and invitations' };
      case '/my-pentests': return { title: 'My Pentests', subtitle: 'Your assigned penetration tests' };
      default: return { title: 'ThreatAtlas', subtitle: 'Security platform' };
    }
  };

  const pageInfo = getPageInfo();

  return (
    <div className="flex items-center gap-4 animate-fadeIn">
      <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-primary/10 to-primary/5 border border-primary/20 shadow-sm transition-all duration-300 hover:shadow-md hover:scale-105">
        <Shield className="h-4 w-4 text-primary transition-transform duration-300 group-hover:rotate-12" />
      </div>
      <div className="flex flex-col gap-0.5">
        <span className="text-base font-semibold tracking-tight bg-gradient-to-r from-foreground to-foreground/80 bg-clip-text">{pageInfo.title}</span>
        <span className="text-xs text-muted-foreground font-medium">{pageInfo.subtitle}</span>
      </div>
    </div>
  );
}

/** Redirects external pentesters away from internal-only routes. */
function InternalOnly({ children }: { children: React.ReactNode }) {
  const { isExternalPentester } = useAuth();
  if (isExternalPentester) return <Navigate to="/my-pentests" replace />;
  return <>{children}</>;
}

function AppContent() {
  const { isExternalPentester } = useAuth();

  return (
    <>
      <AppSidebar />
      <SidebarInset>
        <header className="sticky top-0 z-50 flex h-16 shrink-0 items-center gap-4 border-b border-border/60 bg-background/95 backdrop-blur-xl supports-[backdrop-filter]:bg-background/80 px-6 shadow-sm transition-all duration-300">
          <div className="flex items-center gap-4">
            <SidebarTrigger className="hover:bg-muted/70 transition-all duration-200 rounded-lg p-2 -ml-2 hover:scale-105" />
            <Separator orientation="vertical" className="h-7 bg-border/60" />
            <HeaderBreadcrumb />
          </div>
        </header>
        <main className="flex-1 bg-gradient-to-br from-background via-muted/20 to-background">
          <Routes>
            <Route path="/" element={isExternalPentester ? <Navigate to="/my-pentests" replace /> : <Dashboard />} />
            <Route path="/my-pentests" element={<MyPentests />} />
            <Route path="/products" element={<InternalOnly><Products /></InternalOnly>} />
            <Route path="/products/:productId" element={<InternalOnly><ProductDetails /></InternalOnly>} />
            <Route path="/diagrams" element={<InternalOnly><Diagrams /></InternalOnly>} />
            <Route path="/knowledge" element={<InternalOnly><KnowledgeBase /></InternalOnly>} />
            <Route path="/pentests/:pentestId" element={<PentestDetail />} />
            <Route path="/analytics" element={<InternalOnly><Analytics /></InternalOnly>} />
            <Route path="/reports" element={<InternalOnly><Reports /></InternalOnly>} />
            <Route path="/users" element={<InternalOnly><UserManagement /></InternalOnly>} />
          </Routes>
        </main>
      </SidebarInset>
    </>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/accept-invitation/:token" element={<AcceptInvitation />} />
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <SidebarProvider>
                  <AppContent />
                </SidebarProvider>
              </ProtectedRoute>
            }
          />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
