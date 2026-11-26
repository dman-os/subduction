//! Tests for connection management (`add_connection`, `remove_connection`, `disconnect`).

use subduction_core::{
    connection::test_utils::{MockConnection, new_test_subduction},
    peer::{
        id::PeerId,
        session::{Session, TEST_LOCAL},
    },
};
use testresult::TestResult;

#[tokio::test]
async fn test_add_connection() -> TestResult {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    let conn = MockConnection::new().authenticated();
    let fresh = subduction.add_connection(conn).await?;

    assert!(fresh);
    assert_eq!(subduction.connected_peer_ids().await.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_add_same_connection_twice_returns_false() -> TestResult {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    let conn = MockConnection::new().authenticated();
    let fresh1 = subduction.add_connection(conn.clone()).await?;
    let fresh2 = subduction.add_connection(conn).await?;

    assert!(fresh1);
    assert!(!fresh2);
    assert_eq!(subduction.connected_peer_ids().await.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_remove_connection() -> TestResult {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    let conn = MockConnection::new().authenticated();
    let _fresh = subduction.add_connection(conn.clone()).await?;
    assert_eq!(subduction.connected_peer_ids().await.len(), 1);

    let removed = subduction.remove_connection_for_test(&conn).await;
    assert_eq!(removed, Some(true));
    assert_eq!(subduction.connected_peer_ids().await.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_remove_nonexistent_connection_returns_none() {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    // Remove a connection that was never added
    let conn = MockConnection::with_peer_id(PeerId::new([99u8; 32])).authenticated();
    let removed = subduction.remove_connection_for_test(&conn).await;
    assert_eq!(removed, None);
}

#[tokio::test]
async fn test_add_different_peers_increases_count() -> TestResult {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    let conn1 = MockConnection::with_peer_id(PeerId::new([1u8; 32])).authenticated();
    let conn2 = MockConnection::with_peer_id(PeerId::new([2u8; 32])).authenticated();

    subduction.add_connection(conn1).await?;
    subduction.add_connection(conn2).await?;

    assert_eq!(subduction.connected_peer_ids().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn test_disconnect_removes_connection() -> TestResult {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    let conn = MockConnection::new().authenticated();
    let _fresh = subduction.add_connection(conn.clone()).await?;

    let removed = subduction.disconnect(&conn).await?;
    assert!(removed);
    assert_eq!(subduction.connected_peer_ids().await.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_disconnect_nonexistent_returns_false() -> TestResult {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    let conn = MockConnection::with_peer_id(PeerId::new([99u8; 32])).authenticated();
    let removed = subduction.disconnect(&conn).await?;
    assert!(!removed);

    Ok(())
}

#[tokio::test]
async fn test_disconnect_all_removes_all_connections() -> TestResult {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    let conn1 = MockConnection::with_peer_id(PeerId::new([1u8; 32])).authenticated();
    let conn2 = MockConnection::with_peer_id(PeerId::new([2u8; 32])).authenticated();

    subduction.add_connection(conn1).await?;
    subduction.add_connection(conn2).await?;
    assert_eq!(subduction.connected_peer_ids().await.len(), 2);

    subduction.disconnect_all().await?;
    assert_eq!(subduction.connected_peer_ids().await.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_disconnect_from_peer_removes_specific_peer() -> TestResult {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    let peer_id1 = PeerId::new([1u8; 32]);
    let peer_id2 = PeerId::new([2u8; 32]);
    let conn1 = MockConnection::with_peer_id(peer_id1).authenticated();
    let conn2 = MockConnection::with_peer_id(peer_id2).authenticated();

    subduction.add_connection(conn1).await?;
    subduction.add_connection(conn2).await?;
    assert_eq!(subduction.connected_peer_ids().await.len(), 2);

    let removed = subduction
        .disconnect_from_peer(&Session::new(peer_id1, TEST_LOCAL))
        .await?;
    assert!(removed);
    assert_eq!(subduction.connected_peer_ids().await.len(), 1);
    assert!(!subduction.connected_peer_ids().await.contains(&peer_id1));
    assert!(subduction.connected_peer_ids().await.contains(&peer_id2));

    Ok(())
}

#[tokio::test]
async fn test_disconnect_from_nonexistent_peer_returns_false() {
    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();

    let peer_id = PeerId::new([1u8; 32]);
    #[allow(clippy::unwrap_used)]
    let removed = subduction
        .disconnect_from_peer(&Session::new(peer_id, TEST_LOCAL))
        .await
        .unwrap();
    assert!(!removed);
}

#[tokio::test]
async fn test_sessions_to_one_peer_under_different_principals_are_independent() -> TestResult {
    use subduction_core::authenticated::{Authenticated, Direction};

    let (subduction, _listener_fut, _actor_fut) = new_test_subduction();
    let peer = PeerId::new([7u8; 32]);
    let node = PeerId::new([8u8; 32]);
    let shared = PeerId::new([9u8; 32]);
    let as_node = Session::new(peer, node);
    let as_shared = Session::new(peer, shared);

    let node_conn = Authenticated::new_for_test_as(
        MockConnection::with_peer_id(peer),
        peer,
        node,
        Direction::Dialed,
    );
    let shared_conn = Authenticated::new_for_test_as(
        MockConnection::with_peer_id(peer),
        peer,
        shared,
        Direction::Dialed,
    );
    assert_eq!(node_conn.session(), as_node);
    assert_eq!(shared_conn.session(), as_shared);

    // Both connections are fresh: the second is not a replacement of the first.
    assert!(subduction.add_connection(node_conn.clone()).await?);
    assert!(subduction.add_connection(shared_conn.clone()).await?);
    assert_eq!(subduction.connected_peer_ids().await.len(), 1);
    assert_eq!(subduction.connected_sessions().await.len(), 2);
    assert_eq!(subduction.connection_count(&as_node).await, 1);
    assert_eq!(subduction.connection_count(&as_shared).await, 1);
    assert!(subduction.conn_mux_invariant_holds(&as_node).await);
    assert!(subduction.conn_mux_invariant_holds(&as_shared).await);

    // A session is only ever addressed through its own connection.
    assert!(subduction.get_connection(&as_node).await == Some(node_conn.clone()));
    assert!(subduction.get_connection(&as_shared).await == Some(shared_conn.clone()));
    assert!(
        subduction
            .get_connection(&Session::new(peer, PeerId::new([10u8; 32])))
            .await
            .is_none()
    );

    // Closing one session leaves the other, and its multiplexer, in place.
    assert!(subduction.disconnect_from_peer(&as_shared).await?);
    assert_eq!(subduction.connection_count(&as_shared).await, 0);
    assert_eq!(subduction.mux_count(&as_shared).await, 0);
    assert_eq!(subduction.connection_count(&as_node).await, 1);
    assert_eq!(subduction.mux_count(&as_node).await, 1);
    assert_eq!(subduction.connected_peer_ids().await.len(), 1);

    // Removing the last connection of the node session removes the peer.
    assert_eq!(
        subduction.remove_connection_for_test(&node_conn).await,
        Some(true)
    );
    assert!(subduction.connected_peer_ids().await.is_empty());
    Ok(())
}
