function makeOutputUnit() {
    const urlParams = new URLSearchParams(window.location.search);
    const queryArgs = Array.from(urlParams.entries());
    return {
        hostname: window.location.hostname,
        path: window.location.pathname,
        hash: window.location.hash,
        queryArgs: queryArgs,
        browser: navigator.userAgent,
        protocol: window.location.protocol,
        origin: window.location.origin,
    };
}

async function sendUnit(unit) {
    const url = "/external-api/v0-unstable/web/send-event";
    try {
        const response = await fetch(url, {
            method: "POST",
            body: JSON.stringify(unit),
        });
        if (!response.ok) {
            throw new Error(`Response status: ${response.status}`);
        }

        await response.json();
    } catch (error) {
        console.error(error.message);
    }
}

if (typeof module != "undefined") {
    module.exports = {makeOutputUnit, sendUnit};
}
