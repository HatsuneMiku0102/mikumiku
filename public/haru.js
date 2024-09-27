document.addEventListener('DOMContentLoaded', function () {
    const chatBox = document.getElementById('chat-box');
    const chatContent = document.getElementById('chat-content');
    const chatInput = document.getElementById('chat-input');
    const sendMessageButton = document.getElementById('send-message');
    const haruChatTrigger = document.getElementById('haru-chat-trigger');
    const closeChatButton = document.getElementById('close-chat');

    // Open the chat box when the trigger is clicked
    haruChatTrigger.addEventListener('click', function () {
        chatBox.style.display = 'flex';
    });

    // Close the chat box when the close button is clicked
    closeChatButton.addEventListener('click', function () {
        chatBox.style.display = 'none';
    });

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
        // Placeholder - here you can integrate the OpenAI API using fetch or axios
        return new Promise(resolve => {
            setTimeout(() => {
                resolve("This is a response from Haru via GPT-4");
            }, 1000);
        });
    }
});
