const express = require('express');
const { identifier } = require('../middlewares/identification');
const postsController = require('../controllers/postsController');

const router = express.Router();

router.get('/all-posts', postsController.getPosts);
router.get('/single-post', postsController.singlePost);
router.post('/create-post', identifier, postsController.createPost);

router.put('/update-post', identifier, postsController.updatePost);
// router.delet('/delete-post', identifier, authController.verificationCode);


module.exports = router;
