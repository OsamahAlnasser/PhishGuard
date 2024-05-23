// Send a message to the background script indicating that the content script is ready.
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'showAlert') {
        alert(request.message);
    }
});
