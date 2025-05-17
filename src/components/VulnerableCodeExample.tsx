
import React, { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Code, AlertCircle, CheckCircle } from 'lucide-react';

const VulnerableCodeExample: React.FC = () => {
  const [selectedLanguage, setSelectedLanguage] = useState<string>('python');
  
  return (
    <Card className="w-full shadow-md">
      <CardHeader className="bg-gray-800 text-white rounded-t-lg">
        <div className="flex items-center">
          <Code className="h-5 w-5 mr-2" />
          <CardTitle>Code Examples</CardTitle>
        </div>
        <CardDescription className="text-gray-300">
          Vulnerable vs. Secure SQL Query Examples
        </CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <Tabs 
          defaultValue="python" 
          value={selectedLanguage} 
          onValueChange={setSelectedLanguage}
          className="w-full"
        >
          <div className="border-b">
            <TabsList className="bg-gray-100 p-0">
              <TabsTrigger value="python" className="rounded-none data-[state=active]:bg-white">Python</TabsTrigger>
              <TabsTrigger value="node" className="rounded-none data-[state=active]:bg-white">Node.js</TabsTrigger>
              <TabsTrigger value="php" className="rounded-none data-[state=active]:bg-white">PHP</TabsTrigger>
            </TabsList>
          </div>
          
          <TabsContent value="python" className="p-4 space-y-4">
            <div>
              <div className="flex items-center mb-2">
                <AlertCircle className="text-alert-500 mr-2" />
                <h3 className="font-semibold text-alert-700">Vulnerable Code</h3>
              </div>
              <pre className="bg-gray-800 text-gray-100 p-4 rounded overflow-x-auto text-sm">
{`# Vulnerable to SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    if user:
        return "Login successful"
    else:
        return "Login failed"`}
              </pre>
            </div>
            
            <div>
              <div className="flex items-center mb-2">
                <CheckCircle className="text-green-500 mr-2" />
                <h3 className="font-semibold text-green-700">Secure Code</h3>
              </div>
              <pre className="bg-gray-800 text-gray-100 p-4 rounded overflow-x-auto text-sm">
{`# Safe from SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # SECURE: Using parameterized queries
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    cursor.execute(query, (username, password))
    
    user = cursor.fetchone()
    if user:
        return "Login successful"
    else:
        return "Login failed"`}
              </pre>
            </div>
          </TabsContent>
          
          <TabsContent value="node" className="p-4 space-y-4">
            <div>
              <div className="flex items-center mb-2">
                <AlertCircle className="text-alert-500 mr-2" />
                <h3 className="font-semibold text-alert-700">Vulnerable Code</h3>
              </div>
              <pre className="bg-gray-800 text-gray-100 p-4 rounded overflow-x-auto text-sm">
{`// Vulnerable to SQL Injection
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  // VULNERABLE: Direct string concatenation
  const query = "SELECT * FROM users WHERE username = '" + username + 
                "' AND password = '" + password + "'";
  
  db.query(query, (err, results) => {
    if (results.length > 0) {
      res.send('Login successful');
    } else {
      res.send('Login failed');
    }
  });
});`}
              </pre>
            </div>
            
            <div>
              <div className="flex items-center mb-2">
                <CheckCircle className="text-green-500 mr-2" />
                <h3 className="font-semibold text-green-700">Secure Code</h3>
              </div>
              <pre className="bg-gray-800 text-gray-100 p-4 rounded overflow-x-auto text-sm">
{`// Safe from SQL Injection
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  // SECURE: Using parameterized queries
  const query = "SELECT * FROM users WHERE username = ? AND password = ?";
  
  db.query(query, [username, password], (err, results) => {
    if (results.length > 0) {
      res.send('Login successful');
    } else {
      res.send('Login failed');
    }
  });
});`}
              </pre>
            </div>
          </TabsContent>
          
          <TabsContent value="php" className="p-4 space-y-4">
            <div>
              <div className="flex items-center mb-2">
                <AlertCircle className="text-alert-500 mr-2" />
                <h3 className="font-semibold text-alert-700">Vulnerable Code</h3>
              </div>
              <pre className="bg-gray-800 text-gray-100 p-4 rounded overflow-x-auto text-sm">
{`<?php
// Vulnerable to SQL Injection
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $username = $_POST["username"];
  $password = $_POST["password"];
  
  // VULNERABLE: Direct string concatenation
  $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
  
  $result = mysqli_query($conn, $query);
  
  if (mysqli_num_rows($result) > 0) {
    echo "Login successful";
  } else {
    echo "Login failed";
  }
}
?>`}
              </pre>
            </div>
            
            <div>
              <div className="flex items-center mb-2">
                <CheckCircle className="text-green-500 mr-2" />
                <h3 className="font-semibold text-green-700">Secure Code</h3>
              </div>
              <pre className="bg-gray-800 text-gray-100 p-4 rounded overflow-x-auto text-sm">
{`<?php
// Safe from SQL Injection
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $username = $_POST["username"];
  $password = $_POST["password"];
  
  // SECURE: Using prepared statements
  $stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
  $stmt->bind_param("ss", $username, $password);
  $stmt->execute();
  $result = $stmt->get_result();
  
  if ($result->num_rows > 0) {
    echo "Login successful";
  } else {
    echo "Login failed";
  }
  $stmt->close();
}
?>`}
              </pre>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default VulnerableCodeExample;
