/* === WebAuthn & Face-API Helper Functions === */

// Converts ArrayBuffer to Base64 (URL-safe)
function bufferToBase64(buffer) {
    const byteArray = new Uint8Array(buffer);
    let str = '';
    for (let i = 0; i < byteArray.length; i++) {
        str += String.fromCharCode(byteArray[i]);
    }
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Converts Base64 (URL-safe) to ArrayBuffer
function base64ToBuffer(base64) {
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    const str = atob(base64);
    const buffer = new ArrayBuffer(str.length);
    const byteArray = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) {
        byteArray[i] = str.charCodeAt(i);
    }
    return buffer;
}

// Helper to show messages to the user
const messageArea = document.getElementById('message-area');
function showMessage(message, isError = false) {
    if (messageArea) {
        messageArea.innerHTML = ''; // Clear old messages
        const messageEl = document.createElement('p');
        messageEl.textContent = message;
        messageEl.className = isError ? 'message error' : 'message success';
        messageArea.appendChild(messageEl);
    }
}

// Helper to handle fetch responses safely
async function handleFetchResponse(response) {
    if (!response.ok) {
        const text = await response.text();
        let error = text;
        try {
            const data = JSON.parse(text);
            error = data.error || text;
        } catch (e) {
            // It's not JSON, just show the HTML crash report
        }
        throw new Error(error);
    }
    return response.json();
}

/* === AI Model & Camera Setup === */

const video = document.getElementById('video');
const registerButton = document.getElementById('register-button');
const loginButton = document.getElementById('login-button');
const loadingArea = document.getElementById('loading-area');

// Flags to track when setup is complete
let isCameraReady = false;
let isModelsReady = false;

// This function will be called when camera AND models are ready
function checkIfReady() {
    if (isCameraReady && isModelsReady) {
        // Everything is loaded! Enable the buttons.
        if (registerButton) registerButton.disabled = false;
        if (loginButton) loginButton.disabled = false;
        // Hide the "Loading..." message
        if (loadingArea) loadingArea.style.display = 'none';
        // Show a ready message
        showMessage("System is ready.", false);
    }
}

// Function to load AI models
async function loadModels() {
    try {
        await Promise.all([
            faceapi.nets.tinyFaceDetector.loadFromUri('/static/models'),
            faceapi.nets.faceLandmark68Net.loadFromUri('/static/models'),
            faceapi.nets.faceRecognitionNet.loadFromUri('/static/models'),
        ]);
        isModelsReady = true;
        checkIfReady(); // Check if camera is also ready
    } catch (err) {
        console.error("Model Loading Error:", err);
        showMessage("Could not load AI models. Please refresh the page.", true);
    }
}

// Function to start the webcam
async function startVideo() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: {} });
        video.srcObject = stream;
        // A small delay to ensure camera is fully initialized
        video.onloadedmetadata = () => {
            isCameraReady = true;
            checkIfReady(); // Check if models are also ready
        };
    } catch (err) {
        console.error("Camera Error:", err);
        showMessage("Could not access the camera. Please allow camera permissions.", true);
    }
}

// --- START LOADING EVERYTHING ON PAGE LOAD ---
loadModels();
startVideo();

// Helper function to scan for a face
async function getFaceDescriptor() {
    if (!isCameraReady || !isModelsReady) {
        throw new Error("System is not ready yet. Please wait.");
    }
    
    // Detect a single face
    const detection = await faceapi.detectSingleFace(video, new faceapi.TinyFaceDetectorOptions())
                                   .withFaceLandmarks()
                                   .withFaceDescriptor();
    
    if (!detection) {
        throw new Error("No face detected. Please look at the camera.");
    }
    
    return detection.descriptor; // This is the list of 128 numbers
}


/* === 1. HIGH-SECURITY REGISTRATION LOGIC === */

if (registerButton) {
    registerButton.addEventListener('click', async () => {
        const username = document.getElementById('username').value;
        if (!username) {
            showMessage("Please enter a username.", true);
            return;
        }
        
        registerButton.disabled = true; // Disable button to prevent double-clicks
        let faceDescriptor;

        try {
            // --- STEP 1: SCAN FACE ---
            showMessage("Step 1/2: Scanning for face...", false);
            faceDescriptor = await getFaceDescriptor();
            showMessage("Face scan complete! Now follow the fingerprint prompt.", false);
            
            // --- STEP 2: GET FINGERPRINT CHALLENGE ---
            // (We send the face data and get a fingerprint challenge back)
            const response = await fetch('/register-begin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: username,
                    face_descriptor: Array.from(faceDescriptor) // Convert to simple array
                }),
            });
            
            const options = await handleFetchResponse(response);
            
            // Convert challenge data for the browser
            options.challenge = base64ToBuffer(options.challenge);
            options.user.id = base64ToBuffer(options.user.id);

            // --- STEP 3: TRIGGER FINGERPRINT SCAN ---
            const credential = await navigator.credentials.create({
                publicKey: options
            });

            // --- STEP 4: SEND FINGERPRINT DATA TO SERVER ---
            showMessage("Step 2/2: Verifying fingerprint...", false);
            
            // Convert browser data for the server
            const credentialForServer = {
                id: credential.id,
                type: credential.type,
                rawId: bufferToBase64(credential.rawId),
                response: {
                    clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64(credential.response.attestationObject),
                },
            };

            const completeResponse = await fetch('/register-complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(credentialForServer),
            });
            
            const completeData = await handleFetchResponse(completeResponse);
            
            // --- STEP 5: DONE! ---
            showMessage(completeData.message, false);
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);

        } catch (e) {
            // This 'catch' block handles all errors
            showMessage(`Error: ${e.message}`, true);
            registerButton.disabled = false; // Re-enable the button on failure
        }
    });
}


/* === 2. HIGH-SECURITY LOGIN LOGIC === */

if (loginButton) {
    loginButton.addEventListener('click', async () => {
        const username = document.getElementById('username').value;
        if (!username) {
            showMessage("Please enter your username.", true);
            return;
        }
        
        loginButton.disabled = true;

        try {
            // --- STEP 1: GET SAVED DATA & FINGERPRINT CHALLENGE ---
            showMessage("Step 1/2: Checking user and scanning face...", false);
            const response = await fetch('/login-begin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username }),
            });
            
            const data = await handleFetchResponse(response);
            
            const savedFaceDescriptor = new Float32Array(data.face_descriptor);
            const fingerprintOptions = data.fingerprint_options;

            // --- STEP 2: VERIFY FACE LOCALLY ---
            const currentFaceDescriptor = await getFaceDescriptor();
            
            const faceMatcher = new faceapi.FaceMatcher([savedFaceDescriptor]);
            const bestMatch = faceMatcher.findBestMatch(currentFaceDescriptor);

            if (bestMatch.label === 'person 1' && bestMatch.distance < 0.5) {
                // Face is a MATCH! Proceed to fingerprint.
                showMessage("Face scan complete! Now follow the fingerprint prompt.", false);
            } else {
                // Face is NOT a match.
                throw new Error("Face not recognized. Please try again.");
            }

            // --- STEP 3: TRIGGER FINGERPRINT SCAN ---
            // Convert challenge data for the browser
            fingerprintOptions.challenge = base64ToBuffer(fingerprintOptions.challenge);
            if (fingerprintOptions.allowCredentials) {
                for (let cred of fingerprintOptions.allowCredentials) {
                    cred.id = base64ToBuffer(cred.id);
                }
            }

            const assertion = await navigator.credentials.get({
                publicKey: fingerprintOptions
            });

            // --- STEP 4: SEND FINGERPRINT DATA TO SERVER ---
            showMessage("Step 2/2: Verifying fingerprint...", false);
            
            // Convert browser data for the server
            const assertionForServer = {
                id: assertion.id,
                type: assertion.type,
                rawId: bufferToBase64(assertion.rawId),
                response: {
                    clientDataJSON: bufferToBase64(assertion.response.clientDataJSON),
                    authenticatorData: bufferToBase64(assertion.response.authenticatorData),
                    signature: bufferToBase64(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToBase64(assertion.response.userHandle) : null,
                },
            };

            const completeResponse = await fetch('/login-complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(assertionForServer),
            });

            const completeData = await handleFetchResponse(completeResponse);

            // --- STEP 5: DONE! ---
            showMessage(completeData.message, false);
            setTimeout(() => {
                window.location.href = '/success';
            }, 1000);

        } catch (e) {
            // This 'catch' block handles all errors
            showMessage(`Error: ${e.message}`, true);
            loginButton.disabled = false; // Re-enable button on failure
        }
    });
}