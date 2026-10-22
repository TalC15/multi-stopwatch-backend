import fs from 'node:fs';
import path from 'node:path';
const directory='reports';
if (fs.existsSync(directory)) for (const name of fs.readdirSync(directory)) {
  if (!/^(?:unit|pg18)[\w.-]*\.(?:tap|txt|json)$/.test(name)) continue;
  const file=path.join(directory,name); let content=fs.readFileSync(file,'utf8');
  for (const key of ['POSTGRES_PASSWORD','PGPASSWORD','SUBSCRIPTION_TEST_DATABASE_URL','TEST_DATABASE_URL']) {
    const value=process.env[key]; if (value?.length>=8) content=content.split(value).join('[REDACTED]');
  }
  content=content.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,'[REDACTED_JWT]');
  fs.writeFileSync(file,content);
}
