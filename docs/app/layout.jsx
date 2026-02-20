import { ThemeProvider } from 'next-themes';
import Navbar from '@/components/Navbar';
import './globals.css';

export const metadata = {
  title: 'Sentinel - Security Intelligence SDK for Go',
  description: 'Production-grade security middleware for Go/Gin applications. WAF, rate limiting, threat detection, AI analysis, and an embedded dashboard.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen antialiased">
        <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
          <Navbar />
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
