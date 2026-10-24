const quickReplyButton = document.getElementById('apply-quick-reply');
const quickReplySelector = document.getElementById('quick-reply');
const commentField = document.getElementById('comment_content');

if (quickReplyButton && quickReplySelector && commentField) {
  quickReplyButton.addEventListener('click', () => {
    if (quickReplySelector.value) {
      commentField.value = quickReplySelector.value;
      commentField.focus();
    }
  });
}
