document.addEventListener('DOMContentLoaded', function () {
    const chatBox = document.getElementById('chat-box');
    const closeChatButton = document.getElementById('close-chat');
    const sendMessageButton = document.getElementById('send-message');
    const chatInput = document.getElementById('chat-input');
    const chatContent = document.getElementById('chat-content');
    const personalityCircle = document.getElementById('personalityCircle');

    // Establish WebSocket connection
    const socket = io();

    // Function to open chat
    const openChat = () => {
        chatBox.style.display = 'flex';
    };

    // Function to close chat
    const closeChat = () => {
        chatBox.style.display = 'none';
    };

    // Event listeners for opening and closing the chat
    personalityCircle.addEventListener('click', openChat);
    closeChatButton.addEventListener('click', closeChat);

    // Event listener for sending a message
    sendMessageButton.addEventListener('click', async function () {
        await handleUserMessage();
    });

    // Optional: Add enter key support for sending messages
    chatInput.addEventListener('keypress', async function (event) {
        if (event.key === 'Enter') {
            await handleUserMessage();
        }
    });

    // Function to handle user message, send it, and get bot response
    async function handleUserMessage() {
        const userMessage = chatInput.value.trim();
        if (userMessage) {
            addMessageToChat(userMessage, 'user-message');
            chatInput.value = '';
            const botResponse = await getDialogflowResponse(userMessage);
            addMessageToChat(botResponse, 'bot-message');
        }
    }

    // Function to add a message to the chat window
    function addMessageToChat(message, className) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', className);

        if (className === 'bot-message' && isValidURL(message)) {
            // Handle messages with links by creating a clickable anchor element
            const linkElement = document.createElement('a');
            linkElement.href = message;
            linkElement.textContent = message;
            linkElement.target = '_blank';
            linkElement.rel = 'noopener noreferrer';
            messageElement.appendChild(linkElement);
        } else {
            messageElement.textContent = message;
        }

        chatContent.appendChild(messageElement);
        chatContent.scrollTop = chatContent.scrollHeight;
    }

    // Function to check if a string is a valid URL
    function isValidURL(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    // Function to send the user's message to Dialogflow and get the response
    async function getDialogflowResponse(message) {
        try {
            const response = await fetch('/api/dialogflow', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message }),
            });

            if (!response.ok) {
                console.error('Error from server:', response.statusText);
                return 'Sorry, something went wrong.';
            }

            const data = await response.json();
            console.log("Received response from server:", data);

            return data.response || 'Sorry, something went wrong.';
        } catch (error) {
            console.error('Error fetching Dialogflow response:', error);
            return 'Sorry, something went wrong.';
        }
    }

    // Listen for real-time web search results from server
    socket.on('webSearchResult', (data) => {
        console.log('Received web search result:', data);
        if (data && data.response) {
            addMessageToChat(data.response, 'bot-message');
        }
    });
});
