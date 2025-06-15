import React, { useState, useEffect, useCallback } from 'react';
import { Shield, Wifi, Search, Lock, Key, Hash, TestTube, ChevronRight, Server, Globe, GitBranch, Terminal, Copy, AlertTriangle, CheckCircle, RotateCw, MapPin, Target } from 'lucide-react';

// --- MOCK BACKEND API SIMULATIONS ---
// In a real-world application, these functions would make API calls to a secure backend server
// that executes the actual commands. For this educational demo, they simulate the results.

const fakePing = (host) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      if (!host || !/^[a-zA-Z0-9.-]+$/.test(host)) {
        resolve({ error: "Invalid host. Please enter a valid IP address or domain." });
        return;
      }
      const isUp = Math.random() > 0.2;
      if (isUp) {
        const times = Array.from({ length: 4 }, () => (Math.random() * (150 - 10) + 10).toFixed(2));
        const avg = (times.reduce((a, b) => parseFloat(a) + parseFloat(b), 0) / times.length).toFixed(2);
        resolve({ output: `Pinging ${host}...\n` + times.map(t => `Reply from ${host}: time=${t}ms`).join('\n') + `\n\nStatistics:\n  Sent=4, Received=4, Lost=0\n  Avg. RTT: ${avg}ms` });
      } else {
        resolve({ output: `Pinging ${host}...\nRequest timed out.\nRequest timed out.\n\nStatistics:\n  Sent=4, Received=0, Lost=4` });
      }
    }, 1200);
  });
};

const fakePortScan = (host, ports) => {
    return new Promise((resolve) => {
        setTimeout(() => {
            if (!host || !/^[a-zA-Z0-9.-]+$/.test(host)) {
                resolve({ error: "Invalid host." });
                return;
            }
            const commonPorts = { 21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 8080: 'HTTP-Alt' };
            const portList = ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p) && p > 0 && p < 65536);
            if(portList.length === 0) {
                 resolve({ error: "Invalid port list. Please use comma-separated numbers (e.g., 80,443,8080)." });
                 return;
            }
            const results = portList.map(port => ({
                port,
                status: Math.random() < 0.3 || commonPorts[port] ? 'open' : 'closed',
                service: commonPorts[port] || 'unknown'
            }));
            resolve({ results });
        }, 2000);
    });
};

const fakeDnsLookup = (domain) => {
    return new Promise(resolve => {
        setTimeout(() => {
             if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
                resolve({ error: "Invalid domain name." });
                return;
            }
            resolve({
                A: [`${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`],
                MX: [{ priority: 10, exchange: `mail.${domain}` }],
                TXT: [`"v=spf1 include:_spf.${domain} ~all"`],
                NS: [`ns1.parked.com`, `ns2.parked.com`],
            });
        }, 800);
    });
};

const fakeWhois = (domain) => {
    return new Promise(resolve => {
        setTimeout(() => {
            if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
                resolve({ error: "Invalid domain name." });
                return;
            }
            const creationDate = new Date(new Date() - Math.random() * 10 * 365 * 24 * 60 * 60 * 1000).toDateString();
            resolve({
                output: `
Domain: ${domain}
Registrar: Demo Registrar Inc.
Creation Date: ${creationDate}
Registrant: Private Person
`
            });
        }, 1100);
    });
};

const fakeTraceroute = (host) => {
    return new Promise(resolve => {
        if (!host || !/^[a-zA-Z0-9.-]+$/.test(host)) {
            resolve({ error: "Invalid host." });
            return;
        }
        let hops = [];
        let currentIp = `192.168.1.${Math.floor(Math.random()*254)+1}`;
        for (let i = 1; i <= 12; i++) {
            currentIp = `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
            if (Math.random() < 0.1) {
                hops.push({ hop: i, ip: '* * *', rtt: 'Request timed out.' });
            } else {
                 hops.push({ hop: i, ip: currentIp, rtt: `${(Math.random() * 30 + 5 * i).toFixed(2)} ms` });
            }
            if (Math.random() > 0.85) break; // Randomly end trace
        }
        setTimeout(() => resolve({ hops }), 2500);
    });
};

const fakeIpGeo = (ip) => {
    return new Promise(resolve => {
        if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
            resolve({ error: "Invalid IP address format." });
            return;
        }
        const locations = [
            { city: "San Francisco", country: "USA", isp: "Google LLC", lat: 37.77, lon: -122.41 },
            { city: "Ashburn", country: "USA", isp: "Amazon AWS", lat: 39.04, lon: -77.48 },
            { city: "London", country: "UK", isp: "DigitalOcean", lat: 51.50, lon: -0.12 },
            { city: "Singapore", country: "SG", isp: "Singtel", lat: 1.35, lon: 103.81 },
        ];
        setTimeout(() => resolve(locations[Math.floor(Math.random() * locations.length)]), 900);
    });
};

const fakeSubdomainFinder = (domain) => {
    return new Promise(resolve => {
        if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
            resolve({ error: "Invalid domain name." });
            return;
        }
        const subdomains = ['www', 'mail', 'ftp', 'blog', 'dev', 'api', 'shop', 'support', 'staging', 'test', 'portal'];
        const found = subdomains.filter(() => Math.random() > 0.6);
        setTimeout(() => resolve({ subdomains: found.map(s => `${s}.${domain}`) }), 3000);
    });
};

const fakeHttpHeaderAnalyzer = (url) => {
    return new Promise(resolve => {
        try {
            new URL(url);
        } catch(e){
            resolve({ error: "Invalid URL. Please include http:// or https://" });
            return;
        }

        const headers = {
            'Status': '200 OK',
            'Content-Type': 'text/html; charset=UTF-8',
            'Server': 'Demo-Server/1.0',
            'X-Frame-Options': Math.random() > 0.5 ? 'SAMEORIGIN' : 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "script-src 'self'",
            'X-XSS-Protection': '1; mode=block',
        };
        setTimeout(() => resolve({ headers }), 700);
    });
};

const fakeCsrfAnalyzer = (hasToken) => {
    return new Promise(resolve => {
       setTimeout(() => {
           if(hasToken){
               resolve({ status: 'Protected', message: 'CSRF token found and appears valid.', color: 'text-green-400' });
           } else {
                resolve({ status: 'Vulnerable', message: 'No CSRF token found in the form submission.', color: 'text-red-400' });
           }
       }, 500);
    });
};


// --- Main Application Components ---

const App = () => {
  const [activeTool, setActiveTool] = useState('dashboard');
  const [isTermsAccepted, setIsTermsAccepted] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // Map tool IDs to their respective components
  const toolComponents = {
    dashboard: <Dashboard setActiveTool={setActiveTool} />,
    ping: <PingTester />,
    port_scan: <PortScanner />,
    traceroute: <Traceroute />,
    dns_lookup: <DnsWhoisTool />,
    ip_geo: <IpGeolocation />,
    subdomain_finder: <SubdomainFinder />,
    http_headers: <HttpHeaderAnalyzer />,
    xss_tester: <XssSimulator />,
    sql_tester: <SqlInjectionTester />,
    csrf_analyzer: <CsrfTokenAnalyzer />,
    hash_generator: <HashGenerator />,
    base64: <Base64Tools />,
    url_encode: <UrlEncodingTools />,
    bruteforce_sim: <BruteForceSimulator />,
    password_strength: <PasswordStrengthTester />,
  };

  const getToolDetails = (id) => {
    const tools = [ ...TOOL_CATEGORIES.flatMap(c => c.tools) ];
    return tools.find(t => t.id === id) || { name: 'Dashboard', icon: Shield };
  }
  
  const currentTool = getToolDetails(activeTool);

  return (
    <div className="bg-gray-900 text-gray-200 font-mono flex min-h-screen">
      {!isTermsAccepted && <TermsModal onAccept={() => setIsTermsAccepted(true)} />}
      <Sidebar activeTool={activeTool} setActiveTool={setActiveTool} isOpen={sidebarOpen} setOpen={setSidebarOpen} />
      <main className={`flex-1 transition-all duration-300 ${sidebarOpen ? 'ml-64' : 'ml-16'}`}>
        <div className="p-4 md:p-8 h-full overflow-y-auto">
            <Header title={currentTool.name} icon={currentTool.icon} />
            <div className="mt-8">
              {toolComponents[activeTool]}
            </div>
        </div>
      </main>
    </div>
  );
};

const TermsModal = ({ onAccept }) => (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 border border-red-500 rounded-lg shadow-xl p-6 max-w-2xl w-full">
        <div className="flex items-center mb-4">
          <AlertTriangle className="text-red-500 h-8 w-8 mr-3" />
          <h2 className="text-2xl font-bold text-red-400">Legal & Ethical Use Agreement</h2>
        </div>
        <p className="text-gray-300 mb-4">This toolkit is for educational and professional use only. Use it exclusively on systems you have explicit, written permission to test.</p>
        <ul className="list-disc list-inside text-gray-400 space-y-2 mb-6">
          <li>Unauthorized testing is illegal.</li>
          <li>You are responsible for your actions.</li>
          <li>The creators are not liable for misuse.</li>
        </ul>
        <button onClick={onAccept} className="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-4 rounded-lg transition duration-300 flex items-center justify-center">
          <Shield size={20} className="mr-2"/> Agree & Continue
        </button>
      </div>
    </div>
);

const TOOL_CATEGORIES = [
    { name: "Network Tools", icon: Wifi, tools: [
            { id: 'ping', name: 'Ping Tester', icon: Terminal },
            { id: 'port_scan', name: 'Port Scanner', icon: Search },
            { id: 'traceroute', name: 'Traceroute', icon: GitBranch },
    ]},
    { name: "Info Gathering", icon: Server, tools: [
            { id: 'dns_lookup', name: 'DNS & WHOIS', icon: Search },
            { id: 'ip_geo', name: 'IP Geolocation', icon: Globe },
            { id: 'subdomain_finder', name: 'Subdomain Finder', icon: GitBranch },
            { id: 'http_headers', name: 'Header Analyzer', icon: TestTube },
    ]},
    { name: "Web Security", icon: Lock, tools: [
            { id: 'xss_tester', name: 'XSS Simulator', icon: TestTube },
            { id: 'sql_tester', name: 'SQLi Tester', icon: TestTube },
            { id: 'csrf_analyzer', name: 'CSRF Analyzer', icon: TestTube },
    ]},
    { name: "Crypto Tools", icon: Hash, tools: [
            { id: 'hash_generator', name: 'Hash Generator', icon: Hash },
            { id: 'base64', name: 'Base64', icon: Hash },
            { id: 'url_encode', name: 'URL Encoder', icon: Hash },
    ]},
    { name: "Password Tools", icon: Key, tools: [
            { id: 'bruteforce_sim', name: 'Brute-force Sim', icon: Key },
            { id: 'password_strength', name: 'Password Strength', icon: Key },
    ]}
];

const Sidebar = ({ activeTool, setActiveTool, isOpen, setOpen }) => (
    <div className={`fixed top-0 left-0 h-full bg-gray-900/70 backdrop-blur-lg border-r border-gray-700/50 transition-all duration-300 ${isOpen ? 'w-64' : 'w-16'}`}>
        <div className="flex items-center justify-between h-16 px-4 border-b border-gray-700/50">
            {isOpen && <h1 className="text-xl font-bold text-green-400">HackerKit</h1>}
            <button onClick={() => setOpen(!isOpen)} className="text-gray-400 hover:text-green-400">
                <ChevronRight className={`transition-transform duration-300 ${isOpen ? '' : 'rotate-180'}`} />
            </button>
        </div>
        <nav className="mt-4 px-2 overflow-y-auto h-[calc(100vh-4rem)]">
            <SidebarLink id="dashboard" name="Dashboard" icon={Shield} activeTool={activeTool} setActiveTool={setActiveTool} isOpen={isOpen} />
            <hr className="my-4 border-gray-700/50"/>
            {TOOL_CATEGORIES.map((category) => (
                <div key={category.name} className="mb-2">
                    {isOpen ? <h3 className="px-2 py-1 text-xs font-semibold text-gray-500 uppercase tracking-wider">{category.name}</h3>
                            : <div className="flex justify-center py-2"><category.icon className="h-5 w-5 text-gray-500"/></div>}
                    {category.tools.map(tool => <SidebarLink key={tool.id} {...tool} activeTool={activeTool} setActiveTool={setActiveTool} isOpen={isOpen} />)}
                </div>
            ))}
        </nav>
    </div>
);

const SidebarLink = ({ id, name, icon: Icon, activeTool, setActiveTool, isOpen }) => (
    <a href="#" onClick={(e) => { e.preventDefault(); setActiveTool(id); }}
        className={`flex items-center py-2 px-2 rounded-md text-sm font-medium transition-colors duration-200 ${activeTool === id ? 'bg-green-500/10 text-green-400' : 'text-gray-400 hover:bg-gray-700/50'} ${!isOpen && 'justify-center'}`}>
        <Icon className={`h-5 w-5 ${isOpen && 'mr-3'}`} />{isOpen && name}
    </a>
);

const Header = ({ title, icon: Icon }) => (
    <div className="flex items-center space-x-4 border-b border-gray-700/50 pb-4">
        <div className="p-3 bg-gray-800 rounded-lg"><Icon className="h-6 w-6 text-green-400" /></div>
        <h1 className="text-3xl font-bold text-gray-100">{title}</h1>
    </div>
);

const Dashboard = ({ setActiveTool }) => {
    const [searchTerm, setSearchTerm] = useState('');

    const allTools = TOOL_CATEGORIES.flatMap(c => c.tools);
    const filteredTools = allTools.filter(tool =>
        tool.name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div>
            <div className="mb-8 flex flex-col md:flex-row justify-between items-center gap-4">
                 <p className="text-gray-400">Select a tool from the sidebar or a card below to begin.</p>
                 <div className="relative w-full md:w-auto">
                    <input
                        type="text"
                        placeholder="Search tools..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full bg-gray-800 border-2 border-gray-700 rounded-lg pl-10 pr-4 py-2 focus:outline-none focus:border-green-500"
                    />
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={20} />
                </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredTools.map(tool => (
                     <ToolCard
                        key={tool.id}
                        {...tool}
                        onClick={() => setActiveTool(tool.id)}
                    />
                ))}
            </div>

            {filteredTools.length === 0 && (
                <div className="text-center py-16">
                    <p className="text-gray-400 text-lg">No tools found matching "{searchTerm}"</p>
                </div>
            )}
        </div>
    );
};

const ToolCard = ({ name, icon: Icon, onClick }) => (
    <div onClick={onClick} className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-6 hover:bg-gray-700/50 hover:border-green-400/50 transition-all duration-300 cursor-pointer group">
        <div className="flex items-center space-x-4">
            <Icon className="h-8 w-8 text-gray-400 group-hover:text-green-400 transition-colors" />
            <div>
                <h3 className="text-lg font-semibold text-gray-200 group-hover:text-green-400">{name}</h3>
                <p className="text-sm text-gray-500">Launch Tool</p>
            </div>
        </div>
    </div>
);

const OutputDisplay = ({ children, isLoading, loadingText, initialText }) => (
    <div className="w-full bg-black border border-gray-700 rounded-lg p-4 min-h-[24rem] overflow-y-auto">
        <pre className="text-sm text-gray-300 whitespace-pre-wrap">
            {isLoading && <div className="flex items-center text-yellow-400"><RotateCw className="animate-spin h-4 w-4 mr-3" /><span>{loadingText}</span></div>}
            {!isLoading && !children && <span className="text-gray-500">{initialText}</span>}
            {!isLoading && children}
        </pre>
    </div>
);

// --- Individual Tool Components ---

const PingTester = () => {
    const [target, setTarget] = useState('');
    const [result, setResult] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (!target) { setError('Please enter a target host.'); return; }
        setIsLoading(true);
        setResult('');
        const response = await fakePing(target);
        if (response.error) { setError(response.error); } 
        else { setResult(response.output); }
        setIsLoading(false);
    };

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Send ICMP echo requests to a host to check for reachability.</p>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row items-center gap-4 mb-6">
                <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="e.g., 8.8.8.8 or google.com" className="flex-grow w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500 transition-colors" disabled={isLoading}/>
                <button type="submit" className="w-full sm:w-auto px-6 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 transition-colors disabled:bg-gray-600 flex items-center justify-center" disabled={isLoading}>
                    <Terminal className="mr-2 h-5 w-5" />{isLoading ? 'Pinging...' : 'Ping'}
                </button>
            </form>
            {error && <div className="bg-red-500/10 border border-red-500 text-red-400 p-4 rounded-lg mb-6">{error}</div>}
            <OutputDisplay isLoading={isLoading} loadingText={`Pinging ${target}...`} initialText="# Ping output will appear here...">
                {result}
            </OutputDisplay>
        </div>
    );
};

const PortScanner = () => {
    const [target, setTarget] = useState('');
    const [ports, setPorts] = useState('80,443,8080');
    const [results, setResults] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (!target) { setError('Please enter a target host.'); return; }
        setIsLoading(true);
        setResults([]);
        const response = await fakePortScan(target, ports);
        if (response.error) { setError(response.error); }
        else { setResults(response.results); }
        setIsLoading(false);
    };

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Scan for open TCP ports on a target host.</p>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row items-center gap-4 mb-6">
                <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Target IP or Domain" className="flex-grow w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500" disabled={isLoading} />
                <input type="text" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="e.g., 22,80,443" className="flex-grow w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500" disabled={isLoading} />
                <button type="submit" className="w-full sm:w-auto px-6 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 disabled:bg-gray-600 flex items-center justify-center" disabled={isLoading}>
                    <Search className="mr-2 h-5 w-5" />{isLoading ? 'Scanning...' : 'Scan'}
                </button>
            </form>
            {error && <div className="bg-red-500/10 border border-red-500 text-red-400 p-4 rounded-lg mb-6">{error}</div>}
            <OutputDisplay isLoading={isLoading} loadingText={`Scanning ${target}...`} initialText="# Scan results will appear here...">
                {results.length > 0 && results.map(r => (
                    <div key={r.port} className={`flex justify-between items-center ${r.status === 'open' ? 'text-green-400' : 'text-gray-500'}`}>
                        <span>PORT {r.port}/{r.service}</span>
                        <span>{r.status.toUpperCase()}</span>
                    </div>
                ))}
            </OutputDisplay>
        </div>
    );
};

const Traceroute = () => {
    const [target, setTarget] = useState('');
    const [results, setResults] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (!target) { setError('Please enter a target host.'); return; }
        setIsLoading(true);
        setResults([]);
        const response = await fakeTraceroute(target);
        if (response.error) { setError(response.error); } 
        else { setResults(response.hops); }
        setIsLoading(false);
    };

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Trace the network path to a destination host.</p>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row items-center gap-4 mb-6">
                <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="e.g., 8.8.8.8 or google.com" className="flex-grow w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500" disabled={isLoading} />
                <button type="submit" className="w-full sm:w-auto px-6 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 disabled:bg-gray-600 flex items-center justify-center" disabled={isLoading}>
                    <GitBranch className="mr-2 h-5 w-5" />{isLoading ? 'Tracing...' : 'Trace'}
                </button>
            </form>
            {error && <div className="bg-red-500/10 border border-red-500 text-red-400 p-4 rounded-lg mb-6">{error}</div>}
            <OutputDisplay isLoading={isLoading} loadingText={`Tracing route to ${target}...`} initialText="# Trace results will appear here...">
                {results.length > 0 && results.map(r => (
                    <div key={r.hop}>
                        <span className="w-8 inline-block text-gray-500">{r.hop}</span>
                        <span className="w-48 inline-block">{r.ip}</span>
                        <span>{r.rtt}</span>
                    </div>
                ))}
            </OutputDisplay>
        </div>
    );
};

const IpGeolocation = () => {
    const [ip, setIp] = useState('8.8.8.8');
    const [result, setResult] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (!ip) { setError('Please enter an IP address.'); return; }
        setIsLoading(true);
        setResult(null);
        const response = await fakeIpGeo(ip);
        if (response.error) { setError(response.error); } 
        else { setResult(response); }
        setIsLoading(false);
    };

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Find the approximate geographic location of an IP address.</p>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row items-center gap-4 mb-6">
                <input type="text" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g., 8.8.8.8" className="flex-grow w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500" disabled={isLoading} />
                <button type="submit" className="w-full sm:w-auto px-6 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 disabled:bg-gray-600 flex items-center justify-center" disabled={isLoading}>
                    <MapPin className="mr-2 h-5 w-5" />{isLoading ? 'Locating...' : 'Locate'}
                </button>
            </form>
            {error && <div className="bg-red-500/10 border border-red-500 text-red-400 p-4 rounded-lg mb-6">{error}</div>}
            {isLoading && <div className="text-center text-yellow-400">Locating IP...</div>}
            {result && (
                <div className="bg-gray-800/50 p-6 rounded-lg">
                    <h3 className="text-xl font-bold text-green-400 mb-4">Location for {ip}</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <p><strong>Country:</strong> {result.country}</p>
                            <p><strong>City:</strong> {result.city}</p>
                            <p><strong>ISP:</strong> {result.isp}</p>
                        </div>
                        <div className="bg-gray-700 h-48 rounded-lg flex items-center justify-center text-gray-500 italic">
                            Map simulation centered on {result.city}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

const SubdomainFinder = () => {
    const [domain, setDomain] = useState('');
    const [results, setResults] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (!domain) { setError('Please enter a domain.'); return; }
        setIsLoading(true);
        setResults([]);
        const response = await fakeSubdomainFinder(domain);
        if (response.error) { setError(response.error); } 
        else { setResults(response.subdomains); }
        setIsLoading(false);
    };

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Discover subdomains for a given target domain.</p>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row items-center gap-4 mb-6">
                <input type="text" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="e.g., google.com" className="flex-grow w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500" disabled={isLoading} />
                <button type="submit" className="w-full sm:w-auto px-6 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 disabled:bg-gray-600 flex items-center justify-center" disabled={isLoading}>
                    <Search className="mr-2 h-5 w-5" />{isLoading ? 'Finding...' : 'Find'}
                </button>
            </form>
            {error && <div className="bg-red-500/10 border border-red-500 text-red-400 p-4 rounded-lg mb-6">{error}</div>}
            <OutputDisplay isLoading={isLoading} loadingText={`Searching subdomains of ${domain}...`} initialText="# Found subdomains will appear here...">
                {results.length > 0 ? results.join('\n') : (!isLoading && <span className="text-gray-500">No subdomains found for this demo.</span>)}
            </OutputDisplay>
        </div>
    );
};

const HttpHeaderAnalyzer = () => {
    const [url, setUrl] = useState('https://google.com');
    const [results, setResults] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (!url) { setError('Please enter a URL.'); return; }
        setIsLoading(true);
        setResults(null);
        const response = await fakeHttpHeaderAnalyzer(url);
        if (response.error) { setError(response.error); } 
        else { setResults(response.headers); }
        setIsLoading(false);
    };
    
    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Inspect HTTP response headers from a target URL.</p>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row items-center gap-4 mb-6">
                <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="e.g., https://google.com" className="flex-grow w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500" disabled={isLoading} />
                <button type="submit" className="w-full sm:w-auto px-6 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 disabled:bg-gray-600 flex items-center justify-center" disabled={isLoading}>
                    <TestTube className="mr-2 h-5 w-5" />{isLoading ? 'Analyzing...' : 'Analyze'}
                </button>
            </form>
            {error && <div className="bg-red-500/10 border border-red-500 text-red-400 p-4 rounded-lg mb-6">{error}</div>}
            <OutputDisplay isLoading={isLoading} loadingText={`Fetching headers from ${url}...`} initialText="# Response headers will appear here...">
                {results && Object.entries(results).map(([key, value]) => (
                    <div key={key}>
                       <span className="text-yellow-400">{key}:</span> {value}
                    </div>
                ))}
            </OutputDisplay>
        </div>
    );
};

const CsrfTokenAnalyzer = () => {
    const [result, setResult] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    
    const runTest = async (hasToken) => {
        setIsLoading(true);
        setResult(null);
        const response = await fakeCsrfAnalyzer(hasToken);
        setResult(response);
        setIsLoading(false);
    }
    
    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Simulate checking a form for a Cross-Site Request Forgery (CSRF) token.</p>
            <div className="flex gap-4 mb-6">
                <button onClick={() => runTest(true)} disabled={isLoading} className="flex-1 px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 disabled:bg-gray-600 flex items-center justify-center">
                    <Shield className="mr-2 h-5 w-5" />Simulate Form with Token
                </button>
                 <button onClick={() => runTest(false)} disabled={isLoading} className="flex-1 px-6 py-3 bg-red-600 text-white font-semibold rounded-lg hover:bg-red-700 disabled:bg-gray-600 flex items-center justify-center">
                    <AlertTriangle className="mr-2 h-5 w-5" />Simulate Form without Token
                </button>
            </div>
            {isLoading && <div className="text-center text-yellow-400">Analyzing form submission...</div>}
            {result && <div className="p-4 bg-gray-800/50 rounded-lg">
                <h3 className={`font-bold ${result.color}`}>Status: {result.status}</h3>
                <p className="mt-2 text-gray-300">{result.message}</p>
            </div>}
        </div>
    );
};


const DnsWhoisTool = () => {
    const [domain, setDomain] = useState('');
    const [dnsResults, setDnsResults] = useState(null);
    const [whoisResult, setWhoisResult] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (!domain) { setError('Please enter a domain.'); return; }
        setIsLoading(true);
        setDnsResults(null);
        setWhoisResult('');
        const [dnsRes, whoisRes] = await Promise.all([fakeDnsLookup(domain), fakeWhois(domain)]);
        if (dnsRes.error || whoisRes.error) { setError(dnsRes.error || whoisRes.error); }
        else { setDnsResults(dnsRes); setWhoisResult(whoisRes.output); }
        setIsLoading(false);
    };

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Perform DNS and WHOIS lookups on a domain.</p>
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row items-center gap-4 mb-6">
                <input type="text" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="e.g., google.com" className="flex-grow w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500" disabled={isLoading} />
                <button type="submit" className="w-full sm:w-auto px-6 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 disabled:bg-gray-600 flex items-center justify-center" disabled={isLoading}>
                    <Search className="mr-2 h-5 w-5" />{isLoading ? 'Looking up...' : 'Lookup'}
                </button>
            </form>
             {error && <div className="bg-red-500/10 border border-red-500 text-red-400 p-4 rounded-lg mb-6">{error}</div>}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <OutputDisplay isLoading={isLoading} loadingText="Querying DNS..." initialText="# DNS records...">
                    {dnsResults && Object.entries(dnsResults).map(([key, values]) => (
                        <div key={key}>
                           <span className="text-yellow-400">{key}:</span>
                           {values.map((v, i) => <div key={i} className="pl-4">{typeof v === 'object' ? `${v.priority} ${v.exchange}`: v}</div>)}
                        </div>
                    ))}
                </OutputDisplay>
                <OutputDisplay isLoading={isLoading} loadingText="Querying WHOIS..." initialText="# WHOIS info...">
                    {whoisResult}
                </OutputDisplay>
            </div>
        </div>
    );
};

const HashGenerator = () => {
    const [input, setInput] = useState('');
    const [hashes, setHashes] = useState({ md5: '', sha1: '', sha256: '', sha512: '' });

    const generateHashes = async (text) => {
        // MD5/SHA1 are for demo; not natively in WebCrypto. We'll simulate them.
        const fakeMd5 = text ? 'simulated-md5-hash-for-demo' : '';
        const fakeSha1 = text ? 'simulated-sha1-hash-for-demo' : '';
        
        const textEncoder = new TextEncoder();
        const sha256Buffer = text ? await crypto.subtle.digest('SHA-256', textEncoder.encode(text)) : null;
        const sha512Buffer = text ? await crypto.subtle.digest('SHA-512', textEncoder.encode(text)) : null;

        const bufferToHex = buffer => buffer ? Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('') : '';

        setHashes({
            md5: fakeMd5,
            sha1: fakeSha1,
            sha256: bufferToHex(sha256Buffer),
            sha512: bufferToHex(sha512Buffer),
        });
    }
    
    useEffect(() => {
        generateHashes(input);
    }, [input]);

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Generate various hashes from input text.</p>
            <textarea value={input} onChange={e => setInput(e.target.value)} placeholder="Type text here..." rows="4" className="w-full p-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500"></textarea>
            <div className="mt-6 space-y-4">
                {Object.entries(hashes).map(([algo, hash]) => (
                    <div key={algo}>
                        <label className="text-sm font-bold text-yellow-400 uppercase">{algo}</label>
                        <div className="flex items-center mt-1">
                            <input type="text" readOnly value={hash} className="flex-grow w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-l-md text-green-400" />
                            <button onClick={() => navigator.clipboard.writeText(hash)} className="p-2 bg-gray-700 hover:bg-gray-600 rounded-r-md"><Copy size={18}/></button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

const Base64Tools = () => {
    const [plain, setPlain] = useState('');
    const [b64, setB64] = useState('');
    const [error, setError] = useState('');

    const handleEncode = () => {
        setError('');
        try { setB64(btoa(plain)); }
        catch(e) { setError("Encoding failed."); }
    };

    const handleDecode = () => {
        setError('');
        try { setPlain(atob(b64)); }
        catch(e) { setError("Invalid Base64 string."); }
    };
    
    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Encode to and decode from Base64.</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label className="block mb-2 font-semibold text-yellow-400">Plain Text</label>
                    <textarea value={plain} onChange={e => setPlain(e.target.value)} rows="6" className="w-full p-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500"></textarea>
                </div>
                <div>
                    <label className="block mb-2 font-semibold text-yellow-400">Base64</label>
                    <textarea value={b64} onChange={e => setB64(e.target.value)} rows="6" className="w-full p-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500"></textarea>
                </div>
            </div>
            <div className="flex justify-center gap-4 mt-4">
                <button onClick={handleEncode} className="px-6 py-2 bg-green-600 hover:bg-green-700 rounded-lg">Encode &raquo;</button>
                <button onClick={handleDecode} className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg">&laquo; Decode</button>
            </div>
             {error && <div className="text-center bg-red-500/10 text-red-400 p-3 rounded-lg mt-4">{error}</div>}
        </div>
    );
};

const UrlEncodingTools = () => {
    const [decoded, setDecoded] = useState('');
    const [encoded, setEncoded] = useState('');

    const handleEncode = () => setEncoded(encodeURIComponent(decoded));
    const handleDecode = () => setDecoded(decodeURIComponent(encoded));

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Encode and decode URL components.</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label className="block mb-2 font-semibold text-yellow-400">Decoded URL</label>
                    <textarea value={decoded} onChange={e => setDecoded(e.target.value)} placeholder="https://example.com/?q=test value" rows="6" className="w-full p-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500"></textarea>
                </div>
                <div>
                    <label className="block mb-2 font-semibold text-yellow-400">Encoded URL</label>
                    <textarea value={encoded} onChange={e => setEncoded(e.target.value)} placeholder="https%3A%2F%2Fexample.com%2F%3Fq%3Dtest%20value" rows="6" className="w-full p-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500"></textarea>
                </div>
            </div>
            <div className="flex justify-center gap-4 mt-4">
                <button onClick={handleEncode} className="px-6 py-2 bg-green-600 hover:bg-green-700 rounded-lg">Encode &raquo;</button>
                <button onClick={handleDecode} className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg">&laquo; Decode</button>
            </div>
        </div>
    );
};

const XssSimulator = () => {
    const [input, setInput] = useState('<b onmouseover="alert(\'XSS PoC\')">Hover over me!</b>');
    const [output, setOutput] = useState('');

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-2">Simulate reflected Cross-Site Scripting (XSS). Enter a payload below.</p>
            <p className="text-yellow-400 text-sm mb-6"><AlertTriangle size={16} className="inline mr-2"/>The rendered output is intentionally unsanitized for demonstration purposes.</p>
            <textarea value={input} onChange={e => setInput(e.target.value)} rows="4" className="w-full p-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500"></textarea>
            <button onClick={() => setOutput(input)} className="mt-4 px-6 py-2 bg-green-600 hover:bg-green-700 rounded-lg">Render</button>
            
            <div className="mt-6">
                <h3 className="font-semibold text-yellow-400 mb-2">Rendered Output:</h3>
                <div className="w-full p-4 bg-gray-100 text-black border border-gray-700 rounded-lg" dangerouslySetInnerHTML={{ __html: output }}></div>
            </div>
        </div>
    );
};

const SqlInjectionTester = () => {
    const [payload, setPayload] = useState("' OR 1=1; --");
    const [result, setResult] = useState('');
    const basicPayloads = ["' OR 1=1; --", "admin'--", "1' UNION SELECT 1,2,3 --"];

    const testPayload = () => {
        if (payload.includes("'") && (payload.toLowerCase().includes('or') || payload.toLowerCase().includes('union'))) {
            setResult({
                status: 'Vulnerable',
                message: 'The payload seems to have bypassed checks. The server responded as if the query was successful.',
                color: 'text-red-400'
            });
        } else {
            setResult({
                status: 'Not Vulnerable',
                message: 'The application correctly handled the input.',
                color: 'text-green-400'
            });
        }
    };
    
    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Simulate basic SQL injection attacks to check for vulnerabilities.</p>
            <label className="block mb-2 font-semibold text-yellow-400">SQLi Payload</label>
            <div className="flex gap-2">
                <input type="text" value={payload} onChange={e => setPayload(e.target.value)} className="flex-grow w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500" />
                <button onClick={testPayload} className="px-6 py-2 bg-green-600 hover:bg-green-700 rounded-lg">Test</button>
            </div>
            <div className="mt-2 flex gap-2">
                {basicPayloads.map(p => <button key={p} onClick={() => setPayload(p)} className="text-xs bg-gray-700 hover:bg-gray-600 p-1 rounded">{p}</button>)}
            </div>
            
            {result && <div className="mt-6 p-4 bg-gray-800/50 rounded-lg">
                <h3 className={`font-bold ${result.color}`}>Status: {result.status}</h3>
                <p className="mt-2 text-gray-300">{result.message}</p>
            </div>}
        </div>
    );
};

const PasswordStrengthTester = () => {
    const [password, setPassword] = useState('');
    const checks = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /\d/.test(password),
        symbol: /[!@#$%^&*()]/.test(password),
    };
    const strength = Object.values(checks).filter(Boolean).length;
    const strengthText = ['Very Weak', 'Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'][strength];
    const strengthColor = ['bg-red-600', 'bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-green-500', 'bg-green-400'][strength];

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Analyze password strength based on several criteria.</p>
            <input type="text" value={password} onChange={e => setPassword(e.target.value)} placeholder="Enter password..." className="w-full px-4 py-3 bg-gray-800 border-2 border-gray-700 rounded-lg focus:outline-none focus:border-green-500" />
            
            <div className="mt-4">
                <div className="w-full bg-gray-700 rounded-full h-2.5">
                    <div className={`h-2.5 rounded-full transition-all ${strengthColor}`} style={{width: `${(strength/5)*100}%`}}></div>
                </div>
                <p className="text-right mt-2 font-bold">{strengthText}</p>
            </div>

            <div className="grid grid-cols-2 gap-2 mt-4 text-sm">
                {Object.entries(checks).map(([key, value]) => (
                    <div key={key} className={`flex items-center ${value ? 'text-green-400':'text-gray-500'}`}>
                        {value ? <CheckCircle size={16} className="mr-2"/> : <AlertTriangle size={16} className="mr-2"/>}
                        {key === 'length' && 'At least 8 characters'}
                        {key === 'uppercase' && 'Contains uppercase letter'}
                        {key === 'lowercase' && 'Contains lowercase letter'}
                        {key === 'number' && 'Contains a number'}
                        {key === 'symbol' && 'Contains a symbol'}
                    </div>
                ))}
            </div>
        </div>
    );
};

const BruteForceSimulator = () => {
    const [log, setLog] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [isFound, setIsFound] = useState(false);
    
    const dictionary = ['123456', 'password', 'qwerty', 'admin', 'root', 'secret', 'football'];
    const secretPassword = 'secret';

    const startAttack = () => {
        setIsLoading(true);
        setIsFound(false);
        setLog([]);
        let i = 0;
        const interval = setInterval(() => {
            if (i >= dictionary.length) {
                clearInterval(interval);
                setIsLoading(false);
                if(!isFound) setLog(prev => [...prev, { pass: '', status: 'fail', msg: 'Password not in dictionary.' }]);
                return;
            }
            const pass = dictionary[i];
            if (pass === secretPassword) {
                setLog(prev => [...prev, { pass, status: 'success', msg: `Attempting '${pass}'... SUCCESS!` }]);
                setIsFound(true);
                clearInterval(interval);
                setIsLoading(false);
            } else {
                setLog(prev => [...prev, { pass, status: 'fail', msg: `Attempting '${pass}'... failed.` }]);
            }
            i++;
        }, 500);
    };

    return (
        <div className="max-w-4xl mx-auto">
            <p className="text-gray-400 mb-6">Demonstrates a dictionary attack against a login form. The password is '<span className="text-yellow-400">secret</span>'.</p>
            <div className="bg-gray-800 p-4 rounded-lg">
                <div>Target: <span className="text-gray-400">demo-login.php</span></div>
                <div>Username: <span className="text-gray-400">admin</span></div>
                <div>Passwords List: <span className="text-gray-400">top_passwords.txt ({dictionary.length} words)</span></div>
            </div>
            <button onClick={startAttack} disabled={isLoading} className="mt-4 px-6 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 rounded-lg">Start Attack</button>

            <OutputDisplay isLoading={isLoading} loadingText="Attack in progress..." initialText="# Attack log will appear here...">
                {log.map((entry, i) => (
                     <div key={i} className={entry.status === 'success' ? 'text-green-400' : (entry.pass ? 'text-red-400' : 'text-yellow-400')}>{entry.msg}</div>
                ))}
            </OutputDisplay>
        </div>
    );
}

export default App;
