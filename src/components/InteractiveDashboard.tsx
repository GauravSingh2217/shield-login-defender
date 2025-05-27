
import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Shield, Target, BarChart3, BookOpen, Code, Settings } from 'lucide-react';
import LoginForm from './LoginForm';
import AttackLogs from './AttackLogs';
import SqlInjectionInfo from './SqlInjectionInfo';
import VulnerableCodeExample from './VulnerableCodeExample';
import LoginResponse from './LoginResponse';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from 'recharts';
import { getSqlInjectionLogs, countLogsBySeverity, SqlInjectionSeverity } from '@/utils/sqlInjectionDetector';

interface InteractiveDashboardProps {
  loginAttempted: boolean;
  loginSuccess: boolean;
  attackDetected: boolean;
  username: string;
  attackSeverity?: SqlInjectionSeverity;
  logs: any[];
  onLoginAttempt: (username: string, password: string, isAttack: boolean, severity?: SqlInjectionSeverity) => void;
  onClearLogs: () => void;
}

const InteractiveDashboard: React.FC<InteractiveDashboardProps> = ({
  loginAttempted,
  loginSuccess,
  attackDetected,
  username,
  attackSeverity,
  logs,
  onLoginAttempt,
  onClearLogs,
}) => {
  const [activeSection, setActiveSection] = useState('testing');

  // Prepare chart data
  const getChartData = () => {
    if (logs.length === 0) return [];
    
    const severityCounts = countLogsBySeverity(logs);
    
    return [
      { name: 'High', value: severityCounts[SqlInjectionSeverity.HIGH] },
      { name: 'Medium', value: severityCounts[SqlInjectionSeverity.MEDIUM] },
      { name: 'Low', value: severityCounts[SqlInjectionSeverity.LOW] }
    ];
  };
  
  // Severity colors
  const severityColors = {
    High: '#e11d48',
    Medium: '#f97316',
    Low: '#eab308'
  };

  const sections = [
    {
      id: 'testing',
      title: 'Attack Testing',
      icon: Target,
      description: 'Test SQL injection patterns and see real-time detection'
    },
    {
      id: 'monitoring',
      title: 'Security Monitoring',
      icon: Shield,
      description: 'Monitor and analyze detected attack attempts'
    },
    {
      id: 'analytics',
      title: 'Analytics',
      icon: BarChart3,
      description: 'View statistics and trends of attack patterns'
    },
    {
      id: 'education',
      title: 'Learn',
      icon: BookOpen,
      description: 'Educational content about SQL injection'
    },
    {
      id: 'examples',
      title: 'Code Examples',
      icon: Code,
      description: 'Vulnerable vs secure code examples'
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-red-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">SQL Injection Detection System</h1>
                <p className="text-sm text-gray-600">Interactive Security Testing & Education Platform</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Badge variant="outline" className="text-green-600 border-green-600">
                Enhanced Detection
              </Badge>
              <Badge variant="outline" className="text-blue-600 border-blue-600">
                Encoded Payloads
              </Badge>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="bg-white border-b">
        <div className="container mx-auto px-4">
          <div className="flex space-x-1 overflow-x-auto">
            {sections.map((section) => (
              <Button
                key={section.id}
                variant={activeSection === section.id ? "default" : "ghost"}
                className={`flex items-center space-x-2 whitespace-nowrap ${
                  activeSection === section.id 
                    ? "bg-red-600 text-white hover:bg-red-700" 
                    : "text-gray-600 hover:text-gray-900"
                }`}
                onClick={() => setActiveSection(section.id)}
              >
                <section.icon className="h-4 w-4" />
                <span>{section.title}</span>
              </Button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-8">
        {activeSection === 'testing' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="space-y-6">
              <Card className="border-red-200 shadow-lg">
                <CardHeader className="bg-red-50">
                  <CardTitle className="flex items-center space-x-2">
                    <Target className="h-5 w-5 text-red-600" />
                    <span>Attack Testing Interface</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-6">
                  <LoginForm onLoginAttempt={onLoginAttempt} />
                </CardContent>
              </Card>

              {loginAttempted && (
                <Card>
                  <CardContent className="pt-6">
                    <LoginResponse 
                      success={loginSuccess} 
                      attackDetected={attackDetected}
                      username={username}
                      severity={attackSeverity}
                    />
                  </CardContent>
                </Card>
              )}
            </div>

            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Testing Guidelines</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-semibold text-sm mb-2">Basic Payloads:</h4>
                      <div className="space-y-1 text-sm font-mono bg-gray-50 p-3 rounded">
                        <div>' OR 1=1 --</div>
                        <div>' OR 'a'='a</div>
                        <div>admin'--</div>
                      </div>
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm mb-2">URL Encoded:</h4>
                      <div className="space-y-1 text-sm font-mono bg-gray-50 p-3 rounded">
                        <div>%27%20OR%201%3D1%20--</div>
                        <div>%27%20OR%20%27a%27%3D%27a</div>
                      </div>
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm mb-2">Base64 Encoded:</h4>
                      <div className="space-y-1 text-sm font-mono bg-gray-50 p-3 rounded">
                        <div>J08gMT0x</div>
                        <div>VU5JT04gU0VMRUNUA==</div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        )}

        {activeSection === 'monitoring' && (
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5 text-blue-600" />
                  <span>Security Monitoring Dashboard</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <AttackLogs logs={logs} onClearLogs={onClearLogs} />
              </CardContent>
            </Card>
          </div>
        )}

        {activeSection === 'analytics' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Attack Statistics</CardTitle>
              </CardHeader>
              <CardContent>
                {logs.length > 0 ? (
                  <div className="space-y-4">
                    <BarChart
                      width={400}
                      height={300}
                      data={getChartData()}
                      margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis />
                      <Tooltip />
                      <Bar dataKey="value" fill="#8884d8" name="Count">
                        {getChartData().map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={severityColors[entry.name as keyof typeof severityColors]} />
                        ))}
                      </Bar>
                    </BarChart>
                    <div className="grid grid-cols-3 gap-4">
                      {getChartData().map((entry) => (
                        <div key={entry.name} className="text-center p-4 bg-gray-50 rounded">
                          <div className="text-3xl font-bold">{entry.value}</div>
                          <div className="text-sm text-muted-foreground">{entry.name} Severity</div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <BarChart3 className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No attack data available yet</p>
                    <p className="text-sm">Try some SQL injection patterns to see analytics</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Detection Capabilities</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-3 bg-green-50 rounded">
                    <span className="font-medium">Basic SQL Injection</span>
                    <Badge className="bg-green-600">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-blue-50 rounded">
                    <span className="font-medium">URL Encoded Payloads</span>
                    <Badge className="bg-blue-600">Enhanced</Badge>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-purple-50 rounded">
                    <span className="font-medium">Base64 Encoded</span>
                    <Badge className="bg-purple-600">New</Badge>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-orange-50 rounded">
                    <span className="font-medium">HTML Entity Encoded</span>
                    <Badge className="bg-orange-600">New</Badge>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-gray-50 rounded">
                    <span className="font-medium">Unicode Escaped</span>
                    <Badge className="bg-gray-600">New</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {activeSection === 'education' && (
          <Card>
            <CardContent className="pt-6">
              <SqlInjectionInfo />
            </CardContent>
          </Card>
        )}

        {activeSection === 'examples' && (
          <Card>
            <CardContent className="pt-6">
              <VulnerableCodeExample />
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default InteractiveDashboard;
