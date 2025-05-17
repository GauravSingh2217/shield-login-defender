
import React from 'react';
import { ShieldAlert } from 'lucide-react';

const Header: React.FC = () => {
  return (
    <header className="w-full bg-security-800 text-white shadow-md">
      <div className="container mx-auto py-4 px-6">
        <div className="flex flex-col md:flex-row items-center justify-between">
          <div className="flex items-center mb-4 md:mb-0">
            <ShieldAlert className="h-8 w-8 text-security-300 mr-3" />
            <div>
              <h1 className="text-2xl font-bold">SQL Injection Detection System</h1>
              <p className="text-security-300 text-sm">Educational demonstration for cybersecurity learning</p>
            </div>
          </div>
          <div className="text-sm text-security-300 bg-security-900 py-1 px-3 rounded-md inline-flex items-center">
            <span className="inline-block w-2 h-2 bg-green-400 rounded-full mr-2"></span>
            <span>Demo Environment</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
