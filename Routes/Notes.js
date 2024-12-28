const express = require('express');
const Notes = require('../moduls/Note'); // Adjust path if needed
const routes = express.Router();
const { body, validationResult } = require('express-validator');
const setAuthHeader = require('../middleware/setAuthHeaader');
const passport = require('passport');


// Route to fetch all notes for a user
routes.get('/FetchAllNotes',setAuthHeader, passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const notes = await Notes.find({ user: req.user.id });
        res.json(notes);
    } catch (error) {
        console.error('Error fetching notes:', error.message);
        res.status(500).send("Internal Server Error");
    }
});

// Route to create a new note
routes.post('/CreateNote', setAuthHeader, passport.authenticate('jwt', { session: false }), [
    body('title', 'Title must be at least 3 characters').isLength({ min: 3 }),
    body('description', 'Description must be at least 5 characters').isLength({ min: 5 }),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }
    const { title, description, tag } = req.body;
    try {
        const note = new Notes({
            title, description, tag, user: req.user.id
        });
        const savedNote = await note.save();
        res.json({ success: true,message: "Note has been created", note: savedNote });
    } catch (error) {
        console.error('Error creating note:', error.message);
        res.status(500).send("Internal Server Error");
    }
});

// Route to update an existing note
routes.put('/UpdateNote/:id', setAuthHeader, passport.authenticate('jwt', { session: false }), async (req, res) => {
    const { title, description, tag } = req.body;
    try {
        const newNote = {};
        if (title) newNote.title = title;
        if (description) newNote.description = description;
        if (tag) newNote.tag = tag;

        // Find the note to be updated and update it
        let note = await Notes.findById(req.params.id);
        if (!note) return res.status(404).send("Note not found");

        // Check if the logged-in user is the owner
        if (note.user.toString() !== req.user.id) {
            return res.status(401).send("Not authorized");
        }

        note = await Notes.findByIdAndUpdate(req.params.id, { $set: newNote }, { new: true });
        res.json({ success: true, message: "Note has been updated", note });
    } catch (error) {
        console.error('Error updating note:', error.message);
        res.status(500).send("Internal Server Error");
    }
});

// Route to delete a note
routes.delete('/DeleteNote/:id', setAuthHeader, passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        // Find the note to be deleted and delete it
        let note = await Notes.findById(req.params.id);
        if (!note) return res.status(404).send("Note not found");

        // Allow deletion only if user owns this Note
        if (note.user.toString() !== req.user.id) {
            return res.status(401).send("Not authorized");
        }

        note = await Notes.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: "Note has been deleted", note });
    } catch (error) {
        console.error('Error deleting note:', error.message);
        res.status(500).send("Internal Server Error");
    }
});

module.exports = routes;

