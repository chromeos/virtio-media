// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    collections::VecDeque,
    os::fd::{AsFd, BorrowedFd},
};

use nix::sys::eventfd::EventFd;

/// Manages a pollable queue of events to be sent to the decoder or encoder.
pub struct EventQueue<T> {
    /// Pipe used to signal available events.
    event: EventFd,
    /// FIFO of all pending events.
    pending_events: VecDeque<T>,
}

impl<T> EventQueue<T> {
    /// Create a new event queue.
    pub fn new() -> nix::Result<Self> {
        EventFd::new().map(|event| Self {
            event,
            pending_events: Default::default(),
        })
    }

    /// Add `event` to the queue.
    ///
    /// Returns an error if the poll FD could not be signaled.
    pub fn queue_event(&mut self, event: T) -> nix::Result<()> {
        self.pending_events.push_back(event);
        if self.pending_events.len() == 1 {
            let _ = self.event.write(1)?;
        }

        Ok(())
    }

    /// Read and return the next event, if any.
    pub fn dequeue_event(&mut self) -> Option<T> {
        let event = self.pending_events.pop_front();

        if event.is_some() && self.pending_events.is_empty() {
            let _ = self
                .event
                .read()
                .map_err(|e| log::error!("error while reading event queue fd: {:#}", e));
        }

        event
    }

    /// Remove all the posted events for which `predicate` returns `false`.
    pub fn retain<P: FnMut(&T) -> bool>(&mut self, predicate: P) {
        let was_empty = self.pending_events.is_empty();

        self.pending_events.retain(predicate);

        if !was_empty && self.pending_events.is_empty() {
            let _ = self
                .event
                .read()
                .map_err(|e| log::error!("error while reading event queue fd: {:#}", e));
        }
    }

    /// Returns the number of events currently pending on this queue, i.e. the number of times
    /// `dequeue_event` can be called without blocking.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.pending_events.len()
    }
}

impl<T> AsFd for EventQueue<T> {
    fn as_fd(&self) -> BorrowedFd {
        self.event.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::epoll::*;
    use virtio_media::devices::video_decoder::VideoDecoderBackendEvent;
    use virtio_media::v4l2r::bindings;

    use super::*;

    /// Test basic queue/dequeue functionality of `EventQueue`.
    #[test]
    fn event_queue() {
        let mut event_queue = EventQueue::new().unwrap();

        event_queue
            .queue_event(VideoDecoderBackendEvent::InputBufferDone(1))
            .unwrap();
        assert_eq!(event_queue.len(), 1);
        event_queue
            .queue_event(VideoDecoderBackendEvent::FrameCompleted {
                buffer_id: 1,
                timestamp: bindings::timeval {
                    tv_sec: 10,
                    tv_usec: 42,
                },
                bytes_used: vec![1024],
                is_last: false,
            })
            .unwrap();
        assert_eq!(event_queue.len(), 2);

        assert!(matches!(
            event_queue.dequeue_event(),
            Some(VideoDecoderBackendEvent::InputBufferDone(1))
        ));
        assert_eq!(event_queue.len(), 1);
        assert_eq!(
            event_queue.dequeue_event(),
            Some(VideoDecoderBackendEvent::FrameCompleted {
                buffer_id: 1,
                timestamp: bindings::timeval {
                    tv_sec: 10,
                    tv_usec: 42
                },
                bytes_used: vec![1024],
                is_last: false,
            })
        );
        assert_eq!(event_queue.len(), 0);
    }

    /// Test polling of `TestEventQueue`'s `event_pipe`.
    #[test]
    fn decoder_event_queue_polling() {
        let mut event_queue = EventQueue::new().unwrap();
        let epoll = Epoll::new(EpollCreateFlags::empty()).unwrap();
        epoll
            .add(event_queue.as_fd(), EpollEvent::new(EpollFlags::EPOLLIN, 1))
            .unwrap();

        // The queue is empty, so `event_pipe` should not signal.
        let mut events = [EpollEvent::empty()];
        let nb_fds = epoll.wait(&mut events, EpollTimeout::ZERO).unwrap();
        assert_eq!(nb_fds, 0);
        assert_eq!(event_queue.dequeue_event(), None);

        // `event_pipe` should signal as long as the queue is not empty.
        event_queue
            .queue_event(VideoDecoderBackendEvent::InputBufferDone(1))
            .unwrap();
        assert_eq!(epoll.wait(&mut events, EpollTimeout::ZERO).unwrap(), 1);
        event_queue
            .queue_event(VideoDecoderBackendEvent::InputBufferDone(2))
            .unwrap();
        assert_eq!(epoll.wait(&mut events, EpollTimeout::ZERO).unwrap(), 1);
        event_queue
            .queue_event(VideoDecoderBackendEvent::InputBufferDone(3))
            .unwrap();
        assert_eq!(epoll.wait(&mut events, EpollTimeout::ZERO).unwrap(), 1);

        assert_eq!(
            event_queue.dequeue_event(),
            Some(VideoDecoderBackendEvent::InputBufferDone(1))
        );
        assert_eq!(epoll.wait(&mut events, EpollTimeout::ZERO).unwrap(), 1);
        assert_eq!(
            event_queue.dequeue_event(),
            Some(VideoDecoderBackendEvent::InputBufferDone(2))
        );
        assert_eq!(epoll.wait(&mut events, EpollTimeout::ZERO).unwrap(), 1);
        assert_eq!(
            event_queue.dequeue_event(),
            Some(VideoDecoderBackendEvent::InputBufferDone(3))
        );

        // The queue is empty again, so `event_pipe` should not signal.
        assert_eq!(epoll.wait(&mut events, EpollTimeout::ZERO).unwrap(), 0);
        assert_eq!(event_queue.dequeue_event(), None);
    }
}
