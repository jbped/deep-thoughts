const { User, Thought } = require('../models');
const { AuthenticationError } = require('apollo-server-express');
const { signToken } = require('../utils/auth');

const resolvers = {
    Query: {
        thoughts: async (parent, { username }) => {
            const params = username ? { username } : {};
            return Thought.find(params).sort({ createdAt: -1 })
        },
        thought: async (parent, { _id }) => {
            return Thought.findOne({ _id });
        },
        // get all users
        users: async () => {
            return User.find()
                .select('-__v')
                .populate('friends')
                .populate('thoughts');
        },
        // get a user by username
        user: async (parent, { username }) => {
            return User.findOne({ username })
                .select('-__v -password')
                .populate('friends')
                .populate('thoughts');
        },
        me: async (parent, args, context) => {
            if(context.user) {
                const userData = await User.findOne({ _id: context.user._id })
                    .select('-__v -password')
                    .populate('thoughts')
                    .populate('friends');
                return userData
            }
            throw new AuthenticationError('Not logged in')
        }
    },
    Mutation: {
        addUser: async (parent, args) => {
            const user = await User.create(args);
            const token = signToken(user);

            return { token, user };
        },
        login: async (parent, { email, password }) => {
            const user = await User.findOne({ email });

            if(!user) {
                throw new AuthenticationError('Incorrect credentials')
            }

            const correctPw = await user.isCorrectPassword(password);

            if(!correctPw) {
                throw new AuthenticationError('Incorrect credentials');
            }

            const token = signToken(user)
            return { token, user };
        },
        addThought: async (parent, args, context) => {
            if(context.user) {
                const thought = await Thought.create({ ...args, username: context.user.username });

                await User.findByIdAndUpdate(
                    context.user._id,
                    { $push: { thoughts: thought._id } },
                    { new: true }
                );
                return thought;
            }

            throw new AuthenticationError('You need to be logged in to add a new thought');
        },
        addReaction: async (parent, args, context) => {
            if(context.user) {
                const reaction = await Thought.findByIdAndUpdate(
                    args.thoughtId,
                    { $push: { reactions: { reactionBody: args.reactionBody, username: context.user.username } } },
                    { new: true, runValidators: true }
                );
                return reaction;
            }

            throw new AuthenticationError('You need to be logged in to add a reaction')
        },
        addFriend: async (parent, args, context) => {
            if(context.user) {
                const newFriend = await User.findByIdAndUpdate(
                    context.user._id,
                    { $addToSet: { friends: args.friendId } },
                    { new: true }
                )
                return newFriend;
            }
            throw new AuthenticationError('You need to be logged in to add new friends')
        }
    }
}

module.exports = resolvers;