document.addEventListener('DOMContentLoaded', function () {
    const chatBox = document.getElementById('chat-box');
    const chatTrigger = document.getElementById('haru-chat-trigger');
    const closeChatButton = document.getElementById('close-chat');
    const sendMessageButton = document.getElementById('send-message');
    const chatInput = document.getElementById('chat-input');
    const chatContent = document.getElementById('chat-content');

    // Open the chat box when Haru's circle or the trigger button is clicked
    const openChat = () => {
        chatBox.style.display = 'flex';
    };

    // Close the chat box
    const closeChat = () => {
        chatBox.style.display = 'none';
    };

    // Add event listeners for chat trigger and close button
    chatTrigger.addEventListener('click', openChat);
    closeChatButton.addEventListener('click', closeChat);

    // Send message when the send button is clicked
    sendMessageButton.addEventListener('click', async function () {
        const userMessage = chatInput.value.trim();
        if (userMessage) {
            addMessageToChat(userMessage, 'user-message');
            chatInput.value = '';
            const botResponse = await getGPTResponse(userMessage);
            addMessageToChat(botResponse, 'bot-message');
        }
    });

    // Add a new message to the chat window
    function addMessageToChat(message, className) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', className);
        messageElement.textContent = message;
        chatContent.appendChild(messageElement);
        chatContent.scrollTop = chatContent.scrollHeight; // Scroll to the bottom
    }

    // Mock GPT-4 API call (replace with actual call using OpenAI API)
    async function getGPTResponse(message) {
        try {
            const response = await fetch('/api/gpt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message }),
            });
            const data = await response.json();
            return data.message || 'Sorry, something went wrong.';
        } catch (error) {
            console.error('Error fetching GPT-4 response:', error);
            return 'Sorry, something went wrong.';
        }
    }
});
