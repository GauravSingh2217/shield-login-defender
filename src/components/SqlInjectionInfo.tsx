
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertTriangle, BookOpen, Code, Shield } from 'lucide-react';

const SqlInjectionInfo: React.FC = () => {
  return (
    <Card className="w-full shadow-md">
      <CardHeader className="bg-security-700 text-white rounded-t-lg">
        <div className="flex items-center">
          <BookOpen className="h-5 w-5 mr-2" />
          <CardTitle>SQL Injection Guide</CardTitle>
        </div>
        <CardDescription className="text-security-200">
          Educational information about SQL injection attacks
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <Tabs defaultValue="what">
          <TabsList className="w-full grid grid-cols-3">
            <TabsTrigger value="what">What is SQLi?</TabsTrigger>
            <TabsTrigger value="examples">Examples</TabsTrigger>
            <TabsTrigger value="prevention">Prevention</TabsTrigger>
          </TabsList>
          <TabsContent value="what" className="p-4 space-y-4">
            <div className="space-y-2">
              <h3 className="text-lg font-semibold flex items-center">
                <AlertTriangle className="h-5 w-5 mr-2 text-orange-500" />
                Definition
              </h3>
              <p>
                SQL Injection is a code injection technique that exploits vulnerabilities in 
                applications that interact with databases. Attackers insert malicious SQL statements 
                into entry fields to manipulate the application's database.
              </p>
            </div>
            <div className="space-y-2">
              <h3 className="text-lg font-semibold">Impact</h3>
              <ul className="list-disc pl-5 space-y-1">
                <li>Unauthorized access to sensitive data</li>
                <li>Bypassing authentication</li>
                <li>Data manipulation or deletion</li>
                <li>Execution of administrative operations on the database</li>
                <li>Potential for complete system compromise</li>
              </ul>
            </div>
          </TabsContent>
          
          <TabsContent value="examples" className="p-4 space-y-4">
            <div className="space-y-2">
              <h3 className="text-lg font-semibold flex items-center">
                <Code className="h-5 w-5 mr-2 text-blue-500" />
                Common SQL Injection Payloads
              </h3>
              
              <div className="space-y-3">
                <div className="bg-gray-50 p-3 rounded border">
                  <p className="font-semibold">Authentication Bypass:</p>
                  <pre className="bg-black text-green-400 p-2 rounded mt-1 overflow-x-auto text-sm font-mono">
                    ' OR 1=1 --{'\n'}
                    ' OR '1'='1{'\n'}
                    admin' --
                  </pre>
                </div>
                
                <div className="bg-gray-50 p-3 rounded border">
                  <p className="font-semibold">UNION Attacks:</p>
                  <pre className="bg-black text-green-400 p-2 rounded mt-1 overflow-x-auto text-sm font-mono">
                    ' UNION SELECT username, password FROM users --{'\n'}
                    ' UNION SELECT NULL, table_name FROM information_schema.tables --
                  </pre>
                </div>
                
                <div className="bg-gray-50 p-3 rounded border">
                  <p className="font-semibold">Batch Queries:</p>
                  <pre className="bg-black text-green-400 p-2 rounded mt-1 overflow-x-auto text-sm font-mono">
                    '; DROP TABLE users --{'\n'}
                    '; INSERT INTO users VALUES ('hacker', 'password') --
                  </pre>
                </div>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="prevention" className="p-4 space-y-4">
            <div className="space-y-2">
              <h3 className="text-lg font-semibold flex items-center">
                <Shield className="h-5 w-5 mr-2 text-security-600" />
                Prevention Techniques
              </h3>
              <ul className="list-disc pl-5 space-y-2">
                <li>
                  <span className="font-semibold">Prepared Statements (Parameterized Queries)</span>
                  <p className="mt-1 text-sm">
                    Separate SQL code from user data to prevent injection.
                  </p>
                </li>
                <li>
                  <span className="font-semibold">Input Validation</span>
                  <p className="mt-1 text-sm">
                    Strictly validate and sanitize all user inputs.
                  </p>
                </li>
                <li>
                  <span className="font-semibold">ORM Libraries</span>
                  <p className="mt-1 text-sm">
                    Use Object-Relational Mapping libraries which typically handle SQL escaping.
                  </p>
                </li>
                <li>
                  <span className="font-semibold">Least Privilege</span>
                  <p className="mt-1 text-sm">
                    Limit database permissions for application database users.
                  </p>
                </li>
                <li>
                  <span className="font-semibold">WAF (Web Application Firewall)</span>
                  <p className="mt-1 text-sm">
                    Implement WAFs to detect and block common attack patterns.
                  </p>
                </li>
              </ul>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default SqlInjectionInfo;
