import dns from "node:dns/promises"
import { log } from "../utils/log.js";

export async function lookupDns(domain) {
    log.debug("Fetching DNS Info of ", domain);

    // Remove 'www.' prefix for NS queries since NS records are on the root domain
    const rootDomain = domain.replace(/^www\./, '');
    
    const DNS_TIMEOUT = 5000; // 5 seconds for DNS queries
    const resolver = new dns.Resolver();
    const timeoutId = setTimeout(() => resolver.cancel(), DNS_TIMEOUT);
    try {
        const dnsPromises = [
            resolver.resolve4(domain),
            resolver.resolveNs(rootDomain),
            resolver.resolve6(domain)
        ];

        const dnsResults = await Promise.allSettled(dnsPromises);

        const [ipv4Address, nameServers, ipv6Address] = dnsResults.map(result =>
            result.status === 'fulfilled' ? result.value : null
        );

       

        return {
            domain: domain,
            ipv4: ipv4Address,
            ipv6: ipv6Address,
            nameServers: nameServers
        };
    } catch (error) {
        if (error.name === 'ECANCELLED') {
            log.error('DNS Lookup timed out and was forcefully cancelled!');
            return { error: "DNS Lookup timed out and was forcefully cancelled!" };
        }

        log.error(`DNS Lookup Failed  ${error.message}`);
        return { error: "Something went wrong or DNS service is down at the moment" };
    } finally {
        clearTimeout(timeoutId);
    }
}
// lookupDns('github.com');