// **1. Get the current URL of the website**
const currentURL = window.location.href;
console.log("Current URL:", currentURL);

// **2. Read the contents of the "output.txt" file**
fetch('output.txt')
    .then(response => response.text())
    .then(data => {
        const detectionResult = parseInt(data.trim(), 10); // Ensure it's treated as a number

        // **3. Handle values and redirection/alert**
        if (detectionResult === 1) {
            window.location.href = "caution.atwebpages.com/caution.html";
        } else if (detectionResult === 0) {
            alert("This seems like a safe website!");
        } else {
            console.error("Invalid value in output.txt. Expected 0 or 1.");
        }
    })
    .catch(error => {
        console.error('Error reading output.txt:', error);
    }); 
