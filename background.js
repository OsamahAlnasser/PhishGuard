let whitelist = new Set(['chrome', 'newtab', 'startpage', '', 'localhost', 'extensions']);
let lastDomain = null;
let originalRequestUrl = null;
let urlCheckQueue = []; // Queue to hold URL checks
let isCheckingUrl = false;

chrome.tabs.onActivated.addListener(monitorCurrentTab);
chrome.tabs.onUpdated.addListener(onUpdatedListener);

async function monitorCurrentTab() {
    const [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentDomain = extractDomain(currentTab.url);

    if (currentDomain !== lastDomain && !whitelist.has(currentDomain)) {
        originalRequestUrl = currentTab.url;
        queueUrlCheck(originalRequestUrl, currentTab.id); // Add to queue
    }

    processQueue(); // Start processing the queue
}

function onUpdatedListener(tabId, changeInfo, tab) {
    if (changeInfo.url) {
        const newDomain = extractDomain(changeInfo.url);
        if (shouldRedirect(newDomain)) {
            queueUrlCheck(changeInfo.url, tabId); // Add to queue
            processQueue(); // Start processing if not already running
        }
    }
}

function queueUrlCheck(url, tabId) {
    urlCheckQueue.push({ url, tabId }); // Add check to the queue
}

async function processQueue() {
    if (isCheckingUrl || urlCheckQueue.length === 0) return; // Already checking or queue empty

    isCheckingUrl = true;
    const { url, tabId } = urlCheckQueue.shift(); // Get next check from queue

    chrome.tabs.update(tabId, { url: 'http://localhost/loading.html' });
    await checkUrl(url, tabId); // Now check the URL

    isCheckingUrl = false;
    processQueue(); // Process the next item in the queue
}


async function checkUrl(url, tabId) {
    try {
        console.log('Checking URL:', url);

        const response = await fetch('http://localhost:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        console.log('Prediction received:', data.prediction);

        if (data.prediction === 0) {
            // Redirect to the original URL that was intended by the user
            if (url !== originalRequestUrl) {
                chrome.tabs.update(tabId, { url: originalRequestUrl }, () => {
                    if (originalRequestUrl !== 'chrome-extension://dmhhibpgalaicjffifafbpeodagpkfkh/') {
                        chrome.tabs.sendMessage(tabId, {
                            type: 'showAlert',
                            message: 'This seems to be a legitimate website.'
                        });
                    }
                });
            } else {
                if (originalRequestUrl !== 'chrome-extension://dmhhibpgalaicjffifafbpeodagpkfkh/') {
                    chrome.tabs.sendMessage(tabId, {
                        type: 'showAlert',
                        message: 'This seems to be a legitimate website.'
                    });
                }
            }
        } else if (data.prediction === 1) {
            chrome.tabs.update(tabId, { url: 'http://localhost/index.html' });
        }
    } catch (error) {
        console.error('Error checking URL:', error);
        // If there was an error, redirect back to the original URL to allow the user to proceed
        chrome.tabs.update(tabId, { url: originalRequestUrl });
    } finally {
        isCheckingUrl = false;
    }
}


function shouldRedirect(domain) {
    return !whitelist.has(domain) && domain !== lastDomain;
}

function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch (error) {
        console.error("Invalid URL:", url, error);
        return ""; 
    }
}
