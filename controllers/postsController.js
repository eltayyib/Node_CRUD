const { createPostSchema } = require("../middlewares/validator");
const post = require("../models/postsModel");

exports.getPosts = async (req, res) => {
    const { page } = req.query;
    const postsPerPage = 10;

    try {
        let pageNum = 0;
        if (page && page > 1) {
            pageNum = page - 1;
        }

        const result = await post
            .find()
            .sort({ createdAt: -1 })
            .skip(pageNum * postsPerPage)
            .limit(postsPerPage)
            .populate({ path: 'userId', select: 'email' });

        res.status(200).json({ success: true, message: 'posts', data: result });

    } catch (error) {
        console.error("Error fetching posts:", error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};

exports.singlePost = async (req, res) => {
    const { _Id } = req.query;

    try {
        if (!_Id) {
            return res
                .status(400)
                .json({ success: false, message: 'Post ID (_Id) is required.' });
        }

        const result = await post
            .findOne({ _id: _Id })
            .populate({ path: 'userId', select: 'email' });

        if (!result) {
            return res
                .status(404)
                .json({ success: false, message: 'Post not found.' });
        }

        res.status(200).json({ success: true, message: 'single post', data: result });

    } catch (error) {
        console.error("Error fetching single post:", error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};

exports.createPost = async (req, res) => {
    const { title, description } = req.body;
    const { userId } = req.user;

    try {
        const { error } = createPostSchema.validate({
            title,
            description
        });

        if (error) {
            return res
                .status(400)
                .json({ success: false, message: error.details[0].message });
        }

        const result = await post.create({
            title,
            description,
            userId, 
        });

        res.status(201).json({ success: true, message: 'created', data: result });

    } catch (error) {
        console.error("Error creating post:", error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};

exports.updatePost = async (req, res) => {
    const { _id } = req.query;
    const { title, description } = req.body;
    const { userId } = req.user;

    try {
        const { error } = createPostSchema.validate({ title, description });
        if (error) {
            return res
                .status(400)
                .json({ success: false, message: error.details[0].message });
        }

        const existingPost = await post.findById(_id);
        if (!existingPost) {
            return res
                .status(404)
                .json({ success: false, message: 'Post unavailable' });
        }

        if (existingPost.userId.toString() !== userId) {
            return res
                .status(403)
                .json({ success: false, message: 'Unauthorized: Not your post' });
        }

        existingPost.title = title || existingPost.title;
        existingPost.description = description || existingPost.description;

        const result = await existingPost.save();
        res.status(200).json({ success: true, message: 'Post updated', data: result });

    } catch (error) {
        console.error("Error updating post:", error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};
