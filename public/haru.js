document.addEventListener('DOMContentLoaded', function () {
    // Chat Elements
    const chatBox = document.getElementById('chat-box');
    const closeChatButton = document.getElementById('close-chat');
    const sendMessageButton = document.getElementById('send-message');
    const chatInput = document.getElementById('chat-input');
    const chatContent = document.getElementById('chat-content');
    const personalityCircle = document.getElementById('personalityCircle');

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
        const userMessage = chatInput.value.trim();
        if (userMessage) {
            addMessageToChat(userMessage, 'user-message');
            chatInput.value = '';
            const botResponse = await getDialogflowResponse(userMessage);
            addMessageToChat(botResponse, 'bot-message');
        }
    });

    // Function to add a message to the chat window
    function addMessageToChat(message, className) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', className);
        messageElement.textContent = message;
        chatContent.appendChild(messageElement);
        chatContent.scrollTop = chatContent.scrollHeight;
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
            const data = await response.json();
            return data.response || 'Sorry, something went wrong.';
        } catch (error) {
            console.error('Error fetching Dialogflow response:', error);
            return 'Sorry, something went wrong.';
        }
    }

    // Optional: Add enter key support for sending messages
    chatInput.addEventListener('keypress', async function (event) {
        if (event.key === 'Enter') {
            sendMessageButton.click();
        }
    });
});
