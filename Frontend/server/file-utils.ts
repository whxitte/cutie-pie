import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
import { fileURLToPath } from 'url';
import { IP, Service, EnrichedIP, CrackedIP } from './models';
import { parse } from 'csv-parse';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);

// Function to get the base path (Backend directory)
const getBasePath = () => {
    return process.env.SCANNER_BASE || path.resolve(__dirname, '..', '..', 'Backend');
};

// Function to get the scanner path
const getScannerPath = () => {
    const basePath = getBasePath();
    return path.join(basePath, 'logs', 'scanner');
};

// Function to get the config path
const getConfigPath = () => {
    const basePath = getBasePath();
    return path.join(basePath, 'config');
};

// Log the paths being used
const logPaths = () => {
    console.log(`Scanner base path: ${getBasePath()}`);
    console.log('Using paths:', {
        BASE_PATH: getBasePath(),
        SCANNER_PATH: getScannerPath(),
        CONFIG_PATH: getConfigPath()
    });
};

// Ensure all necessary directories exist
export async function ensureDirectoriesExist() {
    const scannerPath = getScannerPath();
    const configPath = getConfigPath();

    const dirs = [
        path.join(scannerPath, 'classified'),
        path.join(scannerPath, 'enriched'),
        path.join(scannerPath, 'cracked'),
        configPath
    ];

    for (const dir of dirs) {
        if (!fs.existsSync(dir)) {
            try {
                fs.mkdirSync(dir, { recursive: true });
            } catch (err: any) {
                if (err.code === 'EACCES') {
                    console.warn(`Warning: Permission denied creating ${dir} (may be owned by root from scanner). Skipping.`);
                } else {
                    throw err;
                }
            }
        }
    }

    // Log the presence of critical files
    const pathsToCheck = [
        { path: path.join(configPath, 'ports.conf'), name: 'ports.conf' },
        { path: path.join(scannerPath, 'all.txt'), name: 'all.txt' },
        { path: path.join(scannerPath, 'classified'), name: 'classified directory' },
        { path: path.join(scannerPath, 'enriched', 'enriched.csv'), name: 'enriched.csv' },
        { path: path.join(scannerPath, 'cracked', 'cracked.csv'), name: 'cracked.csv' }
    ];

    for (const item of pathsToCheck) {
        console.log(`Checking if ${item.name} exists at ${item.path}: ${fs.existsSync(item.path)}`);
    }
}

// Read all IPs from all.txt
export async function getAllIPs(): Promise<IP[]> {
    try {
        const filePath = path.join(getScannerPath(), 'all.txt');
        console.log('Reading all.txt from:', filePath);
        if (!fs.existsSync(filePath)) {
            console.warn(`all.txt not found at ${filePath}`);
            return [];
        }

        const content = await readFile(filePath, 'utf-8');
        console.log('all.txt content (last 5 lines):', content.split('\n').slice(-5).join('\n')); // Log last 5 lines
        const lines = content.split('\n').filter(line => line.trim() !== '');

        const results: IP[] = [];

        for (const line of lines) {
            const parts = line.split(':');

            if (parts.length >= 2) {
                const ip = parts[0];
                const port = parts[1];
                let timestamp: string;

                if (parts.length > 2) {
                    timestamp = parts.slice(2).join(':');
                } else {
                    timestamp = new Date().toISOString();
                }

                results.push({
                    ip,
                    port,
                    timestamp
                });
            } else {
                console.warn(`Invalid line format in all.txt: ${line}`);
            }
        }

        console.log('getAllIPs returning:', results.slice(-5)); // Log last 5 IPs
        return results;
    } catch (error) {
        console.error('Error reading all.txt:', error);
        return [];
    }
}

// Read services from ports.conf
export async function getServices(): Promise<Service[]> {
    try {
        const filePath = path.join(getConfigPath(), 'ports.conf');
        if (!fs.existsSync(filePath)) {
            return [];
        }

        const content = await readFile(filePath, 'utf-8');
        const lines = content.split('\n').filter(line => line.trim() !== '');

        return lines.map(line => {
            const [port, ...serviceParts] = line.split(' # ');
            const service = serviceParts.join(' # ').trim();
            return {
                port: port.trim(),
                service: service || `Port-${port.trim()}`
            };
        });
    } catch (error) {
        console.error('Error reading ports.conf:', error);
        return [];
    }
}

// Add service to ports.conf
export async function addService(port: string, service: string): Promise<boolean> {
    try {
        const filePath = path.join(getConfigPath(), 'ports.conf');
        const existingServices = await getServices();

        if (existingServices.some(s => s.port === port)) {
            return false;
        }

        const newLine = `${port} # ${service}`;
        await writeFile(filePath, fs.existsSync(filePath)
            ? `${await readFile(filePath, 'utf-8').then(content => content.trim())}\n${newLine}`
            : newLine
        );

        return true;
    } catch (error) {
        console.error('Error adding service:', error);
        return false;
    }
}

// Delete service from ports.conf
export async function deleteService(port: string): Promise<boolean> {
    try {
        const filePath = path.join(getConfigPath(), 'ports.conf');
        if (!fs.existsSync(filePath)) {
            return false;
        }

        const content = await readFile(filePath, 'utf-8');
        let serviceName = '';
        const lines = content.split('\n').filter(line => {
            const [p, s] = line.split(' # ').map(s => s.trim());
            if (p === port) {
                serviceName = s.toLowerCase().replace(/[\s()\/]+/g, '-'); // Sanitize service name
                return false;
            }
            return true;
        });

        if (!serviceName) {
            return false; // Service not found
        }

        // Update ports.conf
        await writeFile(filePath, lines.join('\n'));

        // Delete the corresponding classified file
        const classifiedFile = path.join(getScannerPath(), 'classified', `${serviceName}.txt`);
        try {
            await fs.promises.unlink(classifiedFile);
            console.log(`Deleted classified file: ${classifiedFile}`);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error; // Ignore if file doesn't exist
        }

        return true;
    } catch (error) {
        console.error('Error deleting service:', error);
        return false;
    }
}

// Read classified IPs
export async function getClassifiedIPs(): Promise<Record<string, IP[]>> {
    try {
        const classifiedDir = path.join(getScannerPath(), 'classified');
        console.log('Reading classified files from:', classifiedDir);
        if (!fs.existsSync(classifiedDir)) {
            return {};
        }

        const files = await readdir(classifiedDir);
        const services = await getServices();
        const result: Record<string, IP[]> = {};

        for (const file of files) {
            if (!file.endsWith('.txt')) continue;

            const serviceName = file.replace('.txt', '').toLowerCase();
            const filePath = path.join(classifiedDir, file);
            const fileContent = await readFile(filePath, 'utf-8');

            const lines = fileContent.split('\n').filter(line => line.trim() !== '');
            const ips: IP[] = [];

            for (const line of lines) {
                const parts = line.split(':');

                if (parts.length >= 2) {
                    const ip = parts[0];
                    const port = parts[1];
                    let timestamp: string;

                    if (parts.length > 2) {
                        timestamp = parts.slice(2).join(':');
                    } else {
                        timestamp = new Date().toISOString();
                    }

                    ips.push({
                        ip,
                        port,
                        timestamp
                    });
                } else {
                    console.warn(`Invalid line format in ${file}: ${line}`);
                }
            }

            // Remove .reverse() to keep chronological order (newest at bottom)
            result[serviceName] = ips;
        }

        return result;
    } catch (error) {
        console.error('Error reading classified IPs:', error);
        return {};
    }
}

// Read enriched IPs from enriched.csv with optional incremental fetch
export async function getEnrichedIPs(fromLine?: number): Promise<EnrichedIP[]> {
    try {
        const filePath = path.join(getScannerPath(), 'enriched', 'enriched.csv');
        console.log('Debug: Reading enriched.csv from:', filePath);
        if (!fs.existsSync(filePath)) {
            console.log('Debug: enriched.csv does not exist');
            return [];
        }

        const fileContent = await readFile(filePath, 'utf-8');
        console.log('Debug: enriched.csv content (first 500 chars):', fileContent.substring(0, 500));
        if (!fileContent.trim()) {
            console.log('Debug: enriched.csv is empty');
            return [];
        }

        const lines = fileContent.split('\n').filter(line => line.trim() !== '');
        console.log('Debug: Number of lines in enriched.csv:', lines.length);
        if (lines.length <= 1) { // Only headers
            console.log('Debug: Only headers found in enriched.csv');
            return [];
        }

        // If fromLine is specified, only parse lines after that index (excluding header)
        const startLine = fromLine !== undefined ? Math.max(1, fromLine + 1) : 1;
        const linesToParse = lines.slice(startLine);
        console.log('Debug: Lines to parse (from line', startLine, '):', linesToParse.length);

        if (linesToParse.length === 0) {
            console.log('Debug: No new lines to parse');
            return [];
        }

        const parser = parse({
            delimiter: ',',
            columns: ['ip', 'port', 'hostname', 'organization', 'country', 'banner'], // Explicitly define columns
            skip_empty_lines: true,
            trim: true,
            quote: '"',
            escape: '"',
        });

        const records: EnrichedIP[] = [];
        return new Promise((resolve, reject) => {
            parser.on('data', (record) => {
                console.log('Debug: Parsed record:', record);
                if (!record.timestamp) {
                    record.timestamp = new Date().toISOString();
                }
                records.push(record as EnrichedIP);
            });
            parser.on('end', () => {
                console.log('Debug: Finished parsing, total records:', records.length);
                resolve(records);
            });
            parser.on('error', (err) => {
                console.error('Error parsing CSV:', err);
                reject(err);
            });
            parser.write(linesToParse.join('\n'));
            parser.end();
        });
    } catch (error) {
        console.error('Error reading enriched.csv:', error);
        return [];
    }
}

// Read the latest enriched IP from enriched.csv
export async function getLatestEnrichedIP(): Promise<EnrichedIP | null> {
    try {
        const filePath = path.join(getScannerPath(), 'enriched', 'enriched.csv');
        console.log('Debug: Reading latest enriched IP from:', filePath);
        if (!fs.existsSync(filePath)) {
            console.log('Debug: enriched.csv does not exist');
            return null;
        }

        const fileContent = await readFile(filePath, 'utf-8');
        console.log('Debug: enriched.csv content (first 500 chars):', fileContent.substring(0, 500));
        if (!fileContent.trim()) {
            console.log('Debug: enriched.csv is empty');
            return null;
        }

        const lines = fileContent.split('\n').filter(line => line.trim() !== '');
        console.log('Debug: Number of lines in enriched.csv:', lines.length);
        if (lines.length <= 1) { // Only headers
            console.log('Debug: Only headers found in enriched.csv');
            return null;
        }

        // Parse the last line (latest entry)
        const lastLine = lines[lines.length - 1];
        console.log('Debug: Last line to parse:', lastLine);

        // Validate the last line
        const expectedColumns = 6; // ip,port,hostname,organization,country,banner
        const columns = lastLine.split(',').length;
        if (columns !== expectedColumns) {
            console.log('Debug: Last line has incorrect number of columns:', columns, 'expected:', expectedColumns);
            return null;
        }

        const parser = parse({
            delimiter: ',',
            columns: ['ip', 'port', 'hostname', 'organization', 'country', 'banner'], // Explicitly define columns
            skip_empty_lines: true,
            trim: true,
            quote: '"',
            escape: '"',
        });

        const records: EnrichedIP[] = [];
        await new Promise((resolve, reject) => {
            parser.on('data', (record) => {
                console.log('Debug: Parsed latest record:', record);
                if (!record.timestamp) {
                    record.timestamp = new Date().toISOString();
                }
                records.push(record as EnrichedIP);
            });
            parser.on('end', resolve);
            parser.on('error', (err) => {
                console.error('Debug: Error parsing last line:', err);
                reject(err);
            });
            parser.write(lastLine);
            parser.end();
        });

        return records[0] || null;
    } catch (error) {
        console.error('Error reading latest enriched IP:', error);
        return null;
    }
}

// Read cracked IPs from cracked.csv
export async function getCrackedIPs(fromLine?: number): Promise<CrackedIP[]> {
    try {
        const filePath = path.join(getScannerPath(), 'cracked', 'cracked.csv');
        console.log('Debug: Reading cracked.csv from:', filePath);
        if (!fs.existsSync(filePath)) {
            console.log('Debug: cracked.csv does not exist');
            return [];
        }

        const fileContent = await readFile(filePath, 'utf-8');
        console.log('Debug: cracked.csv content (first 500 chars):', fileContent.substring(0, 500));
        if (!fileContent.trim()) {
            console.log('Debug: cracked.csv is empty');
            return [];
        }

        const lines = fileContent.split('\n').filter(line => line.trim() !== '');
        console.log('Debug: Number of lines in cracked.csv:', lines.length);
        if (lines.length <= 1) { // Only headers
            console.log('Debug: Only headers found in cracked.csv');
            return [];
        }

        // If fromLine is specified, only parse lines after that index (excluding header)
        const startLine = fromLine !== undefined ? Math.max(1, fromLine + 1) : 1;
        const linesToParse = lines.slice(startLine);
        console.log('Debug: Lines to parse (from line', startLine, '):', linesToParse.length);

        if (linesToParse.length === 0) {
            console.log('Debug: No new lines to parse');
            return [];
        }

        const parser = parse({
            delimiter: ',',
            columns: ['ip', 'port', 'username', 'password', 'timestamp'], // Explicitly define columns
            skip_empty_lines: true,
            trim: true,
            quote: '"',
            escape: '"',
        });

        const records: CrackedIP[] = [];
        return new Promise((resolve, reject) => {
            parser.on('data', (record) => {
                console.log('Debug: Parsed record:', record);
                records.push(record as CrackedIP);
            });
            parser.on('end', () => {
                console.log('Debug: Finished parsing, total records:', records.length);
                resolve(records);
            });
            parser.on('error', (err) => {
                console.error('Error parsing CSV:', err);
                reject(err);
            });
            parser.write(linesToParse.join('\n'));
            parser.end();
        });
    } catch (error) {
        console.error('Error reading cracked.csv:', error);
        return [];
    }
}

// Call logPaths after index.ts has set SCANNER_BASE
setTimeout(logPaths, 0);